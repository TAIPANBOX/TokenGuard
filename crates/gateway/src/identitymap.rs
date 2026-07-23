//! The declarative identity map: which client key may speak as which agent
//! ids, which unit (business/team) those agents belong to, and what that
//! unit's monthly budget is. Parses and serves `TOKENFUSE_IDENTITY_MAP`
//! (`docs/20-identity-map.md`, sections 2-3 are the spec this module
//! implements).
//!
//! ## Why this exists
//!
//! After the client-keys slice (`crate::clientkeys`, PR #119) the gateway has
//! three disconnected identity layers: a real credential resolved
//! server-side to a `key_id`; a free-form, unauthenticated `x-fuse-agent-id`
//! header; and nothing at all for a business unit or team. Nothing can say
//! "this credential may only speak as these agents, those agents belong to
//! unit `treasury`, and `treasury` has a $2,000 monthly cap". This module
//! adds exactly that linking, declaratively, parsed from one JSON file, with
//! no registry service and no new dependency.
//!
//! This module only parses, validates, and resolves. It does not enforce
//! anything itself: no budget check, no `TOKENFUSE_IDENTITY_STRICT`
//! handling, no `402` or `403`. Those live in the proxy, wired against
//! [`IdentityMap::resolve`] and [`IdentityMap::unit_budget`] in a later
//! slice. [`StrictMode`] is a home for the strict-mode string, kept here
//! because it is part of the same operator surface, not because anything in
//! this module consults it.
//!
//! ## Off unless configured, then fail closed
//!
//! `TOKENFUSE_IDENTITY_MAP` unset means [`IdentityMap::from_path`] is never
//! called and [`IdentityMap::default`] (empty, [`IdentityMap::enabled`]
//! false) is used instead: every [`IdentityMap::resolve`] call returns an
//! unresolved [`Resolution`], exactly today's behavior.
//!
//! Set, and the map has to be genuinely usable: an unreadable path is
//! [`LoadError::Io`], invalid JSON is [`LoadError::Parse`], and a JSON
//! document that fails a validation rule (an unknown unit reference, a
//! duplicate id, a malformed pattern, a non-positive budget) is
//! [`LoadError::Invalid`]. All three refuse to load rather than degrade to
//! "disabled" or "partially applied": a typo in the map must never silently
//! leave spend unattributed when the operator believes it is being tracked,
//! mirroring [`crate::clientkeys::ClientKeys::from_spec`]'s posture for a set
//! but unusable `TOKENFUSE_CLIENT_KEYS`. The one deliberate exception is an
//! empty file (or `{}`): that reads as "not configured", the same reading an
//! unset variable gets, matching a blank `TOKENFUSE_CLIENT_KEYS` spec.
//!
//! ## The map shape
//!
//! Three top-level sections, all optional; unknown fields are tolerated
//! everywhere (the stack-wide additive convention, so no
//! `deny_unknown_fields`):
//!
//! - `units[]`: `{id, name?, owner?, budget_usd_month?}`. A unit without
//!   `budget_usd_month` is attribution-only.
//! - `keys[]`: `{key_id, unit, agents?: [pattern]}`. Binds a
//!   `TOKENFUSE_CLIENT_KEYS` `key_id` to a unit; an empty or missing
//!   `agents` list means "any agent id", attribution without constraint.
//! - `prefixes[]`: `{match: pattern, unit}`. The fallback for calls with no
//!   (or no mapped) key: pure attribution, never a mismatch.
//!
//! A pattern is a literal string, or a string with exactly one `*` which
//! must be the final character (a prefix match). Anything else is rejected
//! at load: no glob engine, no regex, no new dependency.

use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokenfuse_core::Microusd;

/// Governs ONLY the key<->agent binding check (`docs/20-identity-map.md`
/// section 2): whether a mismatch from [`IdentityMap::resolve`] is ignored,
/// surfaced as a warning header, or blocked with `403`. Unit budgets follow
/// `TOKENFUSE_MODE` instead, like every other budget: the money knob governs
/// money, this knob governs identity. Applying the mode is a later slice's
/// job (the proxy); this type only holds the parsed value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum StrictMode {
    #[default]
    Off,
    Warn,
    Enforce,
}

impl std::str::FromStr for StrictMode {
    type Err = String;

    /// Case-insensitive `off`/`warn`/`enforce`; anything else is an error
    /// (mirrors [`tokenfuse_core::mcpreport::Severity`]'s `FromStr`, the only
    /// other parser like this in the stack). Refusing a mistyped mode rather
    /// than guessing at one matches this module's fail-closed posture
    /// elsewhere: the caller decides what an unrecognized value means for
    /// startup, this just will not silently pick one.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_lowercase().as_str() {
            "off" => Ok(StrictMode::Off),
            "warn" => Ok(StrictMode::Warn),
            "enforce" => Ok(StrictMode::Enforce),
            other => Err(format!(
                "invalid strict mode '{other}' (expected off|warn|enforce)"
            )),
        }
    }
}

/// The parsed, validated identity map. Build with [`IdentityMap::from_path`];
/// [`IdentityMap::default`] is the disabled/empty map every gateway starts
/// with when `TOKENFUSE_IDENTITY_MAP` is unset.
#[derive(Debug, Default)]
pub struct IdentityMap {
    units: HashMap<String, Option<Microusd>>,
    keys: HashMap<String, KeyBinding>,
    prefixes: Vec<PrefixBinding>,
}

/// A `keys[]` entry, resolved: which unit a key_id is bound to, and which
/// agent id patterns (if any) constrain what it may present.
#[derive(Debug)]
struct KeyBinding {
    unit: String,
    agents: Vec<Pattern>,
}

/// A `prefixes[]` entry, resolved.
#[derive(Debug)]
struct PrefixBinding {
    pattern: Pattern,
    unit: String,
}

/// The pattern grammar (`docs/20-identity-map.md` section 2): a literal
/// string, or a string with exactly one trailing `*` (prefix match). No glob
/// engine, no regex: this is the whole grammar.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Pattern {
    Literal(String),
    Prefix(String),
}

impl Pattern {
    /// Parses the grammar above, rejecting anything else: a `*` anywhere but
    /// the final character, or more than one `*`.
    fn parse(raw: &str) -> Result<Pattern, String> {
        match raw.matches('*').count() {
            0 => Ok(Pattern::Literal(raw.to_string())),
            1 if raw.ends_with('*') => Ok(Pattern::Prefix(raw[..raw.len() - 1].to_string())),
            _ => Err(format!(
                "invalid pattern {raw:?}: a '*' is only allowed as the final \
                 character (prefix match)"
            )),
        }
    }

    fn matches(&self, agent_id: &str) -> bool {
        match self {
            Pattern::Literal(s) => s == agent_id,
            Pattern::Prefix(prefix) => agent_id.starts_with(prefix.as_str()),
        }
    }
}

/// What [`IdentityMap::resolve`] found for a call's `key_id`/`agent_id`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Resolution<'a> {
    /// The resolved unit, or `None` if nothing in the map matched. Spend
    /// under `None` stays visible in aggregation under the implicit
    /// "unassigned" bucket rather than being dropped
    /// (`docs/20-identity-map.md` section 3).
    pub unit: Option<&'a str>,
    /// Set only when a key was bound to a unit with a non-empty `agents`
    /// list and the presented `agent_id` did not satisfy it. Never set on
    /// the prefix-fallback path: nothing there is authenticated to check
    /// against.
    pub mismatch: Option<Mismatch>,
}

/// A key<->agent binding violation. `reason` is a stable, wire-facing string
/// (used in the `403` body and the `identity_mismatch` agent-event), not a
/// human sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mismatch {
    pub reason: &'static str,
}

/// A `TOKENFUSE_IDENTITY_MAP` that was set but unusable. Startup refuses
/// rather than falling back to "disabled" or "partially applied", mirroring
/// [`crate::clientkeys::EmptySpec`]: a typo must never silently leave spend
/// unattributed when the operator believes it is being tracked.
#[derive(Debug)]
pub enum LoadError {
    /// The path could not be read at all (missing file, permissions, ...).
    Io(PathBuf, std::io::Error),
    /// The bytes were read but are not valid JSON.
    Parse(serde_json::Error),
    /// Valid JSON, but it fails a validation rule. The message names the
    /// offending value: an unknown unit reference, a duplicate id, a
    /// malformed pattern, or a non-positive budget.
    Invalid(String),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Io(path, e) => write!(
                f,
                "TOKENFUSE_IDENTITY_MAP names {} but it could not be read: {e}; refusing \
                 to start rather than run with the identity map silently off",
                path.display()
            ),
            LoadError::Parse(e) => write!(
                f,
                "TOKENFUSE_IDENTITY_MAP is set but is not valid JSON: {e}; refusing to \
                 start rather than run with the identity map silently off"
            ),
            LoadError::Invalid(msg) => write!(
                f,
                "TOKENFUSE_IDENTITY_MAP is set but invalid: {msg}; refusing to start \
                 rather than run with the identity map silently off"
            ),
        }
    }
}

impl std::error::Error for LoadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            LoadError::Io(_, e) => Some(e),
            LoadError::Parse(e) => Some(e),
            LoadError::Invalid(_) => None,
        }
    }
}

/// The wire shape of the JSON file (`docs/20-identity-map.md` section 2).
/// Unknown fields are tolerated everywhere: plain serde default behavior, no
/// `deny_unknown_fields`, matching the stack-wide additive convention. Fields
/// this module has no use for (`units[].name`/`units[].owner`) are simply
/// omitted here rather than kept unread: that omission is itself "unknown
/// field", tolerated the same way a genuinely future field would be.
#[derive(Debug, Deserialize)]
struct WireMap {
    #[serde(default)]
    units: Vec<WireUnit>,
    #[serde(default)]
    keys: Vec<WireKey>,
    #[serde(default)]
    prefixes: Vec<WirePrefix>,
}

#[derive(Debug, Deserialize)]
struct WireUnit {
    id: String,
    #[serde(default)]
    budget_usd_month: Option<f64>,
}

#[derive(Debug, Deserialize)]
struct WireKey {
    key_id: String,
    unit: String,
    #[serde(default)]
    agents: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct WirePrefix {
    #[serde(rename = "match")]
    pattern: String,
    unit: String,
}

impl IdentityMap {
    /// Loads and validates the map at `path` (`TOKENFUSE_IDENTITY_MAP`).
    ///
    /// An empty file (or `{}`) is read as "not configured": the same reading
    /// an unset variable gets, so a blank map cannot accidentally turn
    /// [`enabled`](IdentityMap::enabled) off in one place and on in another.
    /// Anything else that fails to read, parse, or validate refuses via
    /// [`LoadError`] rather than degrading, mirroring
    /// [`crate::clientkeys::ClientKeys::from_spec`]'s posture for a set but
    /// unusable `TOKENFUSE_CLIENT_KEYS`.
    pub fn from_path(path: &Path) -> Result<Self, LoadError> {
        let raw =
            std::fs::read_to_string(path).map_err(|e| LoadError::Io(path.to_path_buf(), e))?;
        Self::parse(&raw)
    }

    /// Parses already-read JSON text. Split out from `from_path` so the
    /// validation-rule tests below exercise it directly, without each one
    /// needing a real file on disk.
    fn parse(raw: &str) -> Result<Self, LoadError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(Self::default());
        }
        let wire: WireMap = serde_json::from_str(trimmed).map_err(LoadError::Parse)?;
        Self::build(wire)
    }

    /// Validates a parsed [`WireMap`] and builds the resolvable form.
    /// Load-time validation only: every violation refuses via
    /// [`LoadError::Invalid`], naming the offending value. Nothing here
    /// degrades a bad entry and continues loading.
    fn build(wire: WireMap) -> Result<Self, LoadError> {
        let mut units: HashMap<String, Option<Microusd>> = HashMap::new();
        for u in wire.units {
            if u.id.trim().is_empty() {
                return Err(LoadError::Invalid(format!(
                    "units[] entry has a blank id {:?} (must be non-empty after trimming \
                     whitespace)",
                    u.id
                )));
            }
            if units.contains_key(&u.id) {
                return Err(LoadError::Invalid(format!(
                    "duplicate units[].id {:?}",
                    u.id
                )));
            }
            let budget = match u.budget_usd_month {
                None => None,
                Some(v) if v.is_finite() && v > 0.0 => Some(Microusd::from_usd(v)),
                Some(v) => {
                    return Err(LoadError::Invalid(format!(
                        "units[].id {:?} has budget_usd_month {v} which must be a finite \
                         number greater than zero",
                        u.id
                    )))
                }
            };
            units.insert(u.id, budget);
        }

        let mut keys: HashMap<String, KeyBinding> = HashMap::new();
        for k in wire.keys {
            if k.key_id.trim().is_empty() {
                return Err(LoadError::Invalid(format!(
                    "keys[] entry has a blank key_id {:?} (must be non-empty after \
                     trimming whitespace)",
                    k.key_id
                )));
            }
            if keys.contains_key(&k.key_id) {
                return Err(LoadError::Invalid(format!(
                    "duplicate keys[].key_id {:?}",
                    k.key_id
                )));
            }
            if !units.contains_key(&k.unit) {
                return Err(LoadError::Invalid(format!(
                    "keys[].key_id {:?} names unit {:?} which is not declared in units[]",
                    k.key_id, k.unit
                )));
            }
            let mut agents = Vec::with_capacity(k.agents.len());
            for pat in &k.agents {
                agents.push(Pattern::parse(pat).map_err(LoadError::Invalid)?);
            }
            keys.insert(
                k.key_id,
                KeyBinding {
                    unit: k.unit,
                    agents,
                },
            );
        }

        let mut prefixes = Vec::with_capacity(wire.prefixes.len());
        for p in wire.prefixes {
            if !units.contains_key(&p.unit) {
                return Err(LoadError::Invalid(format!(
                    "prefixes[] entry matching {:?} names unit {:?} which is not declared \
                     in units[]",
                    p.pattern, p.unit
                )));
            }
            let pattern = Pattern::parse(&p.pattern).map_err(LoadError::Invalid)?;
            prefixes.push(PrefixBinding {
                pattern,
                unit: p.unit,
            });
        }

        Ok(IdentityMap {
            units,
            keys,
            prefixes,
        })
    }

    /// Whether the map carries anything at all: any unit, key binding, or
    /// prefix. `false` on [`IdentityMap::default`].
    #[must_use]
    pub fn enabled(&self) -> bool {
        !self.units.is_empty() || !self.keys.is_empty() || !self.prefixes.is_empty()
    }

    /// Resolves a call's unit and any key<->agent mismatch
    /// (`docs/20-identity-map.md` section 3):
    ///
    /// 1. A non-empty `key_id` bound in `keys[]`: that binding's unit. If
    ///    the binding lists `agents` patterns, an empty `agent_id` is
    ///    `"agent_id_missing"`, one that matches no pattern is
    ///    `"agent_id_not_allowed"`, and a match (or an empty/missing
    ///    `agents` list) is no mismatch.
    /// 2. Otherwise (no `key_id`, or an unbound one): the first `prefixes[]`
    ///    entry in document order whose pattern matches `agent_id`. Never a
    ///    mismatch here: nothing is authenticated to check against.
    /// 3. No match anywhere: `Resolution { unit: None, mismatch: None }`.
    #[must_use]
    pub fn resolve(&self, key_id: &str, agent_id: &str) -> Resolution<'_> {
        if !key_id.is_empty() {
            if let Some(binding) = self.keys.get(key_id) {
                let unit = Some(binding.unit.as_str());
                if binding.agents.is_empty() {
                    return Resolution {
                        unit,
                        mismatch: None,
                    };
                }
                if agent_id.is_empty() {
                    return Resolution {
                        unit,
                        mismatch: Some(Mismatch {
                            reason: "agent_id_missing",
                        }),
                    };
                }
                let matched = binding.agents.iter().any(|p| p.matches(agent_id));
                return Resolution {
                    unit,
                    mismatch: if matched {
                        None
                    } else {
                        Some(Mismatch {
                            reason: "agent_id_not_allowed",
                        })
                    },
                };
            }
        }
        for prefix in &self.prefixes {
            if prefix.pattern.matches(agent_id) {
                return Resolution {
                    unit: Some(prefix.unit.as_str()),
                    mismatch: None,
                };
            }
        }
        Resolution {
            unit: None,
            mismatch: None,
        }
    }

    /// The monthly budget for `unit`, converted to [`Microusd`], or `None` if
    /// the unit is unknown or was declared without `budget_usd_month`
    /// (attribution-only).
    #[must_use]
    pub fn unit_budget(&self, unit: &str) -> Option<Microusd> {
        self.units.get(unit).copied().flatten()
    }

    /// Every unit's monthly budget as a flat map, ready to seed
    /// `UnitLedger::new`. A unit declared without `budget_usd_month`
    /// (attribution-only) is simply absent from the map, matching how a
    /// unit missing from that map reads as "uncapped" downstream.
    #[must_use]
    pub fn unit_budgets(&self) -> HashMap<String, Microusd> {
        self.units
            .iter()
            .filter_map(|(id, budget)| budget.map(|b| (id.clone(), b)))
            .collect()
    }

    /// Every configured `keys[].key_id`, for a startup cross-check against
    /// `TOKENFUSE_CLIENT_KEYS` (a map entry naming a `key_id` no client key
    /// resolves to is a likely typo, worth a warning even though it is not a
    /// load-time refusal). Order is unspecified.
    #[must_use]
    pub fn key_ids(&self) -> Vec<&str> {
        self.keys.keys().map(String::as_str).collect()
    }

    /// How many units are configured (startup log).
    #[must_use]
    pub fn unit_count(&self) -> usize {
        self.units.len()
    }

    /// How many key bindings are configured (startup log).
    #[must_use]
    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write_temp(label: &str, contents: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "tf-identitymap-{label}-{}.json",
            std::process::id()
        ));
        std::fs::write(&path, contents).unwrap();
        path
    }

    // -----------------------------------------------------------------
    // StrictMode
    // -----------------------------------------------------------------

    #[test]
    fn strict_mode_from_str_is_case_insensitive() {
        for (s, want) in [
            ("off", StrictMode::Off),
            ("Off", StrictMode::Off),
            ("OFF", StrictMode::Off),
            ("warn", StrictMode::Warn),
            ("Warn", StrictMode::Warn),
            ("enforce", StrictMode::Enforce),
            ("ENFORCE", StrictMode::Enforce),
            (" enforce ", StrictMode::Enforce),
        ] {
            assert_eq!(s.parse::<StrictMode>(), Ok(want), "input {s:?}");
        }
    }

    #[test]
    fn strict_mode_from_str_rejects_anything_else() {
        for s in ["", "   ", "bogus", "enforced", "0", "warnn"] {
            assert!(
                s.parse::<StrictMode>().is_err(),
                "input {s:?} must be rejected, not silently mapped to a mode"
            );
        }
    }

    #[test]
    fn strict_mode_default_is_off() {
        assert_eq!(StrictMode::default(), StrictMode::Off);
    }

    // -----------------------------------------------------------------
    // Pattern grammar
    // -----------------------------------------------------------------

    #[test]
    fn a_literal_pattern_matches_only_the_exact_string() {
        let p = Pattern::parse("agent://bank.example/treasury/bot-1").unwrap();
        assert!(p.matches("agent://bank.example/treasury/bot-1"));
        assert!(!p.matches("agent://bank.example/treasury/bot-2"));
        assert!(!p.matches("agent://bank.example/treasury/bot-1x"));
        assert!(!p.matches(""));
    }

    #[test]
    fn a_trailing_star_pattern_matches_by_prefix() {
        let p = Pattern::parse("agent://bank.example/treasury/*").unwrap();
        assert!(p.matches("agent://bank.example/treasury/"));
        assert!(p.matches("agent://bank.example/treasury/bot-1"));
        assert!(!p.matches("agent://bank.example/treasury"));
        assert!(!p.matches("agent://bank.example/lending/bot-1"));
    }

    #[test]
    fn a_bare_star_matches_every_agent_id_including_empty() {
        let p = Pattern::parse("*").unwrap();
        assert!(p.matches(""));
        assert!(p.matches("anything"));
    }

    #[test]
    fn a_star_must_be_the_final_character() {
        for bad in ["a*b", "*ab", "ab*cd", "**", "a**", "*a*", "***"] {
            assert!(
                Pattern::parse(bad).is_err(),
                "pattern {bad:?} must be rejected"
            );
        }
    }

    // -----------------------------------------------------------------
    // Load-time behavior: empty / missing / malformed
    // -----------------------------------------------------------------

    #[test]
    fn an_empty_or_blank_document_yields_a_disabled_map() {
        for raw in ["", "   ", "\n", "{}", "  {}  \n"] {
            let map = IdentityMap::parse(raw).expect("blank/empty JSON is 'not configured'");
            assert!(!map.enabled(), "input {raw:?} must yield a disabled map");
            assert_eq!(map.unit_count(), 0);
            assert_eq!(map.key_count(), 0);
        }
    }

    #[test]
    fn from_path_on_a_missing_file_is_an_io_error() {
        let path = std::env::temp_dir().join(format!(
            "tf-identitymap-does-not-exist-{}.json",
            std::process::id()
        ));
        let _ = std::fs::remove_file(&path);
        match IdentityMap::from_path(&path) {
            Err(LoadError::Io(p, _)) => assert_eq!(p, path),
            other => panic!("expected LoadError::Io, got {other:?}"),
        }
    }

    #[test]
    fn malformed_json_is_a_parse_error() {
        match IdentityMap::parse("not json at all") {
            Err(LoadError::Parse(_)) => {}
            other => panic!("expected LoadError::Parse, got {other:?}"),
        }
    }

    #[test]
    fn from_path_reads_a_real_file_end_to_end() {
        let path = write_temp(
            "e2e",
            r#"{"units": [{"id": "treasury", "budget_usd_month": 2000.0}]}"#,
        );
        let map = IdentityMap::from_path(&path).expect("valid file loads");
        assert!(map.enabled());
        assert_eq!(map.unit_count(), 1);
        assert_eq!(
            map.unit_budget("treasury"),
            Some(Microusd::from_usd(2000.0))
        );
        let _ = std::fs::remove_file(&path);
    }

    // -----------------------------------------------------------------
    // Load-time validation refusals
    // -----------------------------------------------------------------

    #[test]
    fn a_blank_unit_id_is_refused() {
        for id in ["", "   "] {
            let raw = format!(r#"{{"units": [{{"id": {id:?}}}]}}"#);
            match IdentityMap::parse(&raw) {
                Err(LoadError::Invalid(msg)) => assert!(msg.contains("blank id")),
                other => panic!("id {id:?}: expected LoadError::Invalid, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_blank_key_id_is_refused() {
        let raw = r#"{"units": [{"id": "u"}], "keys": [{"key_id": "  ", "unit": "u"}]}"#;
        match IdentityMap::parse(raw) {
            Err(LoadError::Invalid(msg)) => assert!(msg.contains("blank key_id")),
            other => panic!("expected LoadError::Invalid, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_unit_ids_are_refused() {
        let raw = r#"{"units": [{"id": "treasury"}, {"id": "treasury"}]}"#;
        match IdentityMap::parse(raw) {
            Err(LoadError::Invalid(msg)) => {
                assert!(msg.contains("duplicate"));
                assert!(msg.contains("treasury"));
            }
            other => panic!("expected LoadError::Invalid, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_key_ids_are_refused() {
        let raw = r#"{
            "units": [{"id": "a"}, {"id": "b"}],
            "keys": [
                {"key_id": "k1", "unit": "a"},
                {"key_id": "k1", "unit": "b"}
            ]
        }"#;
        match IdentityMap::parse(raw) {
            Err(LoadError::Invalid(msg)) => {
                assert!(msg.contains("duplicate"));
                assert!(msg.contains("k1"));
            }
            other => panic!("expected LoadError::Invalid, got {other:?}"),
        }
    }

    #[test]
    fn a_key_naming_an_unknown_unit_is_refused() {
        let raw = r#"{"keys": [{"key_id": "k1", "unit": "ghost"}]}"#;
        match IdentityMap::parse(raw) {
            Err(LoadError::Invalid(msg)) => {
                assert!(msg.contains("k1"));
                assert!(msg.contains("ghost"));
            }
            other => panic!("expected LoadError::Invalid, got {other:?}"),
        }
    }

    #[test]
    fn a_prefix_naming_an_unknown_unit_is_refused() {
        let raw = r#"{"prefixes": [{"match": "agent://x/*", "unit": "ghost"}]}"#;
        match IdentityMap::parse(raw) {
            Err(LoadError::Invalid(msg)) => assert!(msg.contains("ghost")),
            other => panic!("expected LoadError::Invalid, got {other:?}"),
        }
    }

    #[test]
    fn a_zero_or_negative_budget_is_refused() {
        for budget in ["0", "0.0", "-1", "-100.5"] {
            let raw = format!(r#"{{"units": [{{"id": "u", "budget_usd_month": {budget}}}]}}"#);
            match IdentityMap::parse(&raw) {
                Err(LoadError::Invalid(msg)) => assert!(
                    msg.contains("greater than zero"),
                    "budget {budget}: message was {msg:?}"
                ),
                other => panic!("budget {budget}: expected LoadError::Invalid, got {other:?}"),
            }
        }
    }

    #[test]
    fn a_non_finite_budget_is_refused() {
        // NaN/Infinity have no JSON literal syntax, so this validates the
        // rule directly against a hand-built WireMap rather than through
        // parse().
        for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let wire = WireMap {
                units: vec![WireUnit {
                    id: "u".to_string(),
                    budget_usd_month: Some(bad),
                }],
                keys: vec![],
                prefixes: vec![],
            };
            match IdentityMap::build(wire) {
                Err(LoadError::Invalid(msg)) => assert!(msg.contains("finite")),
                other => panic!("budget {bad}: expected LoadError::Invalid, got {other:?}"),
            }
        }
    }

    #[test]
    fn an_invalid_pattern_inside_keys_agents_is_refused() {
        let raw = r#"{
            "units": [{"id": "u"}],
            "keys": [{"key_id": "k1", "unit": "u", "agents": ["a*b"]}]
        }"#;
        match IdentityMap::parse(raw) {
            Err(LoadError::Invalid(msg)) => assert!(msg.contains("a*b")),
            other => panic!("expected LoadError::Invalid, got {other:?}"),
        }
    }

    #[test]
    fn an_invalid_pattern_inside_prefixes_match_is_refused() {
        let raw = r#"{
            "units": [{"id": "u"}],
            "prefixes": [{"match": "*a*", "unit": "u"}]
        }"#;
        match IdentityMap::parse(raw) {
            Err(LoadError::Invalid(msg)) => assert!(msg.contains("*a*")),
            other => panic!("expected LoadError::Invalid, got {other:?}"),
        }
    }

    #[test]
    fn unknown_json_fields_are_tolerated_everywhere() {
        let raw = r#"{
            "unrelated_top_level": true,
            "units": [{"id": "treasury", "name": "Treasury", "owner": "user://x/olena",
                       "budget_usd_month": 2000.0, "extra": 1}],
            "keys": [{"key_id": "k1", "unit": "treasury", "agents": ["a*"], "extra": 1}],
            "prefixes": [{"match": "a*", "unit": "treasury", "extra": 1}]
        }"#;
        let map = IdentityMap::parse(raw).expect("unknown fields must not refuse the load");
        assert!(map.enabled());
        assert_eq!(map.unit_count(), 1);
    }

    // -----------------------------------------------------------------
    // Resolution matrix
    // -----------------------------------------------------------------

    /// The exact example from `docs/20-identity-map.md` section 2.
    const DESIGN_DOC_EXAMPLE: &str = r#"{
      "units": [
        { "id": "treasury", "name": "Treasury", "owner": "user://bank.example/olena",
          "budget_usd_month": 2000.0 }
      ],
      "keys": [
        { "key_id": "treasury-bots", "unit": "treasury",
          "agents": ["agent://bank.example/treasury/*"] }
      ],
      "prefixes": [
        { "match": "agent://bank.example/treasury/*", "unit": "treasury" }
      ]
    }"#;

    #[test]
    fn parses_the_design_doc_example_end_to_end() {
        let map = IdentityMap::parse(DESIGN_DOC_EXAMPLE).expect("the doc's own example must load");
        assert!(map.enabled());
        assert_eq!(map.unit_count(), 1);
        assert_eq!(map.key_count(), 1);
        assert_eq!(map.key_ids(), vec!["treasury-bots"]);
        assert_eq!(
            map.unit_budget("treasury"),
            Some(Microusd::from_usd(2000.0))
        );
    }

    #[test]
    fn a_bound_key_with_an_allowed_agent_resolves_with_no_mismatch() {
        let map = IdentityMap::parse(DESIGN_DOC_EXAMPLE).unwrap();
        let r = map.resolve("treasury-bots", "agent://bank.example/treasury/bot-1");
        assert_eq!(
            r,
            Resolution {
                unit: Some("treasury"),
                mismatch: None
            }
        );
    }

    #[test]
    fn a_bound_key_with_a_disallowed_agent_is_agent_id_not_allowed() {
        let map = IdentityMap::parse(DESIGN_DOC_EXAMPLE).unwrap();
        let r = map.resolve("treasury-bots", "agent://bank.example/lending/bot-1");
        assert_eq!(
            r,
            Resolution {
                unit: Some("treasury"),
                mismatch: Some(Mismatch {
                    reason: "agent_id_not_allowed"
                }),
            }
        );
    }

    #[test]
    fn a_bound_key_with_an_empty_agent_id_is_agent_id_missing() {
        let map = IdentityMap::parse(DESIGN_DOC_EXAMPLE).unwrap();
        let r = map.resolve("treasury-bots", "");
        assert_eq!(
            r,
            Resolution {
                unit: Some("treasury"),
                mismatch: Some(Mismatch {
                    reason: "agent_id_missing"
                }),
            }
        );
    }

    #[test]
    fn a_bound_key_with_a_missing_agents_list_never_mismatches() {
        let raw = r#"{"units": [{"id": "u"}], "keys": [{"key_id": "k1", "unit": "u"}]}"#;
        let map = IdentityMap::parse(raw).unwrap();
        assert_eq!(
            map.resolve("k1", ""),
            Resolution {
                unit: Some("u"),
                mismatch: None
            }
        );
        assert_eq!(
            map.resolve("k1", "literally-anything"),
            Resolution {
                unit: Some("u"),
                mismatch: None
            }
        );
    }

    #[test]
    fn a_bound_key_with_an_explicit_empty_agents_list_never_mismatches() {
        let raw =
            r#"{"units": [{"id": "u"}], "keys": [{"key_id": "k1", "unit": "u", "agents": []}]}"#;
        let map = IdentityMap::parse(raw).unwrap();
        assert_eq!(
            map.resolve("k1", ""),
            Resolution {
                unit: Some("u"),
                mismatch: None
            }
        );
    }

    #[test]
    fn an_unbound_key_falls_through_to_prefixes() {
        let raw = r#"{
            "units": [{"id": "a"}, {"id": "b"}],
            "keys": [{"key_id": "key-a", "unit": "a"}],
            "prefixes": [{"match": "agent://b/*", "unit": "b"}]
        }"#;
        let map = IdentityMap::parse(raw).unwrap();
        // "key-b" has no keys[] binding, so it falls through to the prefix
        // that matches the agent id, exactly as an empty key_id would.
        let r = map.resolve("key-b", "agent://b/bot-1");
        assert_eq!(
            r,
            Resolution {
                unit: Some("b"),
                mismatch: None
            }
        );
        let r_empty = map.resolve("", "agent://b/bot-1");
        assert_eq!(
            r_empty,
            Resolution {
                unit: Some("b"),
                mismatch: None
            }
        );
    }

    #[test]
    fn the_first_matching_prefix_wins_in_document_order() {
        let raw = r#"{
            "units": [{"id": "a"}, {"id": "b"}],
            "prefixes": [
                {"match": "agent://x/*", "unit": "a"},
                {"match": "agent://x/y*", "unit": "b"}
            ]
        }"#;
        let map = IdentityMap::parse(raw).unwrap();
        // Both patterns match; the FIRST one in document order wins, not the
        // more specific one.
        let r = map.resolve("", "agent://x/yz");
        assert_eq!(
            r,
            Resolution {
                unit: Some("a"),
                mismatch: None
            }
        );
    }

    #[test]
    fn nothing_matching_resolves_to_no_unit_and_no_mismatch() {
        let map = IdentityMap::parse(DESIGN_DOC_EXAMPLE).unwrap();
        let r = map.resolve("unknown-key", "agent://somewhere/else");
        assert_eq!(
            r,
            Resolution {
                unit: None,
                mismatch: None
            }
        );
    }

    #[test]
    fn the_default_map_is_disabled_and_resolves_nothing() {
        let map = IdentityMap::default();
        assert!(!map.enabled());
        assert_eq!(
            map.resolve("any-key", "any-agent"),
            Resolution {
                unit: None,
                mismatch: None
            }
        );
        assert_eq!(map.unit_budget("any-unit"), None);
        assert!(map.unit_budgets().is_empty());
        assert!(map.key_ids().is_empty());
    }

    // -----------------------------------------------------------------
    // Budgets
    // -----------------------------------------------------------------

    #[test]
    fn unit_budget_converts_usd_to_microusd() {
        let raw = r#"{"units": [{"id": "treasury", "budget_usd_month": 199.99}]}"#;
        let map = IdentityMap::parse(raw).unwrap();
        assert_eq!(
            map.unit_budget("treasury"),
            Some(Microusd::from_usd(199.99))
        );
    }

    #[test]
    fn a_unit_without_a_budget_is_attribution_only() {
        let raw = r#"{"units": [{"id": "treasury"}]}"#;
        let map = IdentityMap::parse(raw).unwrap();
        assert!(map.enabled());
        assert_eq!(map.unit_budget("treasury"), None);
        assert!(map.unit_budgets().is_empty());
    }

    #[test]
    fn an_unknown_unit_has_no_budget() {
        let map = IdentityMap::parse(DESIGN_DOC_EXAMPLE).unwrap();
        assert_eq!(map.unit_budget("does-not-exist"), None);
    }

    #[test]
    fn unit_budgets_returns_a_flat_map_of_only_capped_units() {
        let raw = r#"{"units": [
            {"id": "treasury", "budget_usd_month": 2000.0},
            {"id": "lending"},
            {"id": "ops", "budget_usd_month": 50.0}
        ]}"#;
        let map = IdentityMap::parse(raw).unwrap();
        let budgets = map.unit_budgets();
        assert_eq!(budgets.len(), 2);
        assert_eq!(budgets.get("treasury"), Some(&Microusd::from_usd(2000.0)));
        assert_eq!(budgets.get("ops"), Some(&Microusd::from_usd(50.0)));
        assert_eq!(budgets.get("lending"), None);
    }

    // -----------------------------------------------------------------
    // key_ids / counts
    // -----------------------------------------------------------------

    #[test]
    fn key_ids_lists_every_configured_key_id() {
        let raw = r#"{
            "units": [{"id": "a"}, {"id": "b"}],
            "keys": [
                {"key_id": "k1", "unit": "a"},
                {"key_id": "k2", "unit": "b"}
            ]
        }"#;
        let map = IdentityMap::parse(raw).unwrap();
        let mut ids = map.key_ids();
        ids.sort_unstable();
        assert_eq!(ids, vec!["k1", "k2"]);
    }

    #[test]
    fn units_only_with_no_keys_or_prefixes_is_still_enabled() {
        let raw = r#"{"units": [{"id": "treasury", "budget_usd_month": 100.0}]}"#;
        let map = IdentityMap::parse(raw).unwrap();
        assert!(map.enabled());
        assert_eq!(map.unit_count(), 1);
        assert_eq!(map.key_count(), 0);
    }
}
