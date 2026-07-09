//! Model router: picks the cheapest model that still meets a task's declared
//! quality tier, before the request is priced and forwarded.
//!
//! FinOps cost optimization only. `proxy::messages` calls [`Router::route`]
//! between `parse_request` and `estimate_cost`: the decision is applied (or,
//! in shadow mode, just reported) before anything downstream prices,
//! reserves, or forwards the call. The router never touches budget,
//! reservation, breaker, or cache logic itself; it only decides which model
//! identity the rest of the pipeline sees.
//!
//! Contract (never routes up by default):
//! - Among a task class's candidates whose declared tier meets the class's
//!   `required_tier`, the router picks whichever is strictly cheaper than the
//!   requested model. If one exists, that is the new model.
//! - If none is cheaper, the requested model is kept, UNLESS the requested
//!   model's own declared tier (from anywhere else in the rules table) is
//!   known and falls below the class's `required_tier`. That is the one case
//!   where a rule explicitly requires a higher tier than what was asked for,
//!   and the router upgrades to the cheapest candidate that satisfies it,
//!   even though it costs more. A model the router has no tier opinion on is
//!   never upgraded, so cost can only go down for models outside the rules
//!   table.

use crate::estimate::estimate_cost;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokenfuse_core::{Microusd, PriceBook};

/// Router operating mode, mirroring the off/shadow/on convention already used
/// by `TOKENFUSE_CACHE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RouterMode {
    /// Routing is disabled: no decision is computed, nothing is added.
    #[default]
    Off,
    /// Compute and report the routing decision (the `x-fuse-router` header)
    /// without rewriting the request or the body sent upstream.
    Shadow,
    /// Rewrite `parsed.model` and the outgoing body's `model` field to the
    /// chosen candidate before pricing, reserving, and forwarding.
    On,
}

/// A model's declared quality tier. Declaration order is the tier order
/// (`Haiku < Sonnet < Opus`), so `tier >= required_tier` is a plain
/// comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    Haiku,
    Sonnet,
    Opus,
}

/// One routing candidate: a model and the tier it satisfies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub model: String,
    pub tier: Tier,
}

/// Routing rule for one task class: the minimum tier the class needs, and the
/// candidate models that can serve it. By convention the list is
/// cheapest-first (for a human reading the rules file), but `route` verifies
/// actual cost against the `PriceBook` rather than trusting this order.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassRule {
    pub required_tier: Tier,
    pub candidates: Vec<Candidate>,
}

/// The full rules table: task class name to rule, plus which class an absent
/// or unrecognized `x-fuse-task-type` falls into.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouterRules {
    pub default_class: String,
    pub classes: HashMap<String, ClassRule>,
}

/// Built-in rules used when `TOKENFUSE_ROUTER_RULES` is unset, empty, or
/// fails to load: a "cheap"/"default" class pinned to a haiku-tier model, and
/// a "hard"/"reasoning" class pinned to sonnet-then-opus tier models. Model
/// names match the exact-priced entries in [`crate::pricebook::default_price_book`].
pub fn default_rules() -> RouterRules {
    let cheap = ClassRule {
        required_tier: Tier::Haiku,
        candidates: vec![Candidate {
            model: "claude-haiku-4-5".to_string(),
            tier: Tier::Haiku,
        }],
    };
    let hard = ClassRule {
        required_tier: Tier::Sonnet,
        candidates: vec![
            Candidate {
                model: "claude-sonnet-4-5".to_string(),
                tier: Tier::Sonnet,
            },
            Candidate {
                model: "claude-opus-4-5".to_string(),
                tier: Tier::Opus,
            },
        ],
    };

    let mut classes = HashMap::new();
    classes.insert("cheap".to_string(), cheap.clone());
    classes.insert("default".to_string(), cheap);
    classes.insert("hard".to_string(), hard.clone());
    classes.insert("reasoning".to_string(), hard);

    RouterRules {
        default_class: "default".to_string(),
        classes,
    }
}

/// The outcome of a routing decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteDecision {
    pub original_model: String,
    pub chosen_model: String,
}

impl RouteDecision {
    fn kept(model: &str) -> Self {
        RouteDecision {
            original_model: model.to_string(),
            chosen_model: model.to_string(),
        }
    }

    /// Whether the router picked a different model than what was requested.
    pub fn routed(&self) -> bool {
        self.original_model != self.chosen_model
    }

    /// The `x-fuse-router` response header value: `"<original>-><chosen>"`
    /// when routed, `"<model>=kept"` otherwise.
    pub fn header_value(&self) -> String {
        if self.routed() {
            format!("{}->{}", self.original_model, self.chosen_model)
        } else {
            format!("{}=kept", self.original_model)
        }
    }
}

/// Picks the cheapest model that still meets a task class's required quality
/// tier. Built from a rules table; see the module doc for the full contract.
pub struct Router {
    pub mode: RouterMode,
    rules: RouterRules,
    /// Flattened model -> declared tier, built once from every class's
    /// candidate list, so `route` can tell whether the REQUESTED model
    /// (which may not belong to the resolved class at all) already meets a
    /// class's bar without rescanning the whole table per request.
    tier_index: HashMap<String, Tier>,
}

impl Router {
    pub fn new(mode: RouterMode, rules: RouterRules) -> Self {
        let tier_index = rules
            .classes
            .values()
            .flat_map(|c| c.candidates.iter())
            .map(|c| (c.model.clone(), c.tier))
            .collect();
        Router {
            mode,
            rules,
            tier_index,
        }
    }

    /// Router mode Off with the built-in default rules table. Used as
    /// `AppState`'s starting point before `serve()` calls `from_env`.
    pub fn disabled() -> Self {
        Router::new(RouterMode::Off, default_rules())
    }

    /// Build from `TOKENFUSE_ROUTER` (off|shadow|on, default off) and
    /// `TOKENFUSE_ROUTER_RULES` (optional path to a JSON rules file). A
    /// present-but-broken path fails open to the built-in default table (the
    /// same fail-open convention `TOKENFUSE_WASM_POLICY` uses in `main.rs`)
    /// rather than crashing startup.
    pub fn from_env() -> Self {
        let mode = match std::env::var("TOKENFUSE_ROUTER").as_deref() {
            Ok("shadow") => RouterMode::Shadow,
            Ok("on") => RouterMode::On,
            _ => RouterMode::Off,
        };
        let rules = match std::env::var("TOKENFUSE_ROUTER_RULES") {
            Ok(path) if !path.is_empty() => match load_rules_file(&path) {
                Ok(rules) => rules,
                Err(e) => {
                    tracing::warn!(
                        %path,
                        "failed to load router rules, using the built-in default table: {e}"
                    );
                    default_rules()
                }
            },
            _ => default_rules(),
        };
        Router::new(mode, rules)
    }

    fn resolve_class(&self, task_class: &str) -> Option<&ClassRule> {
        self.rules
            .classes
            .get(task_class)
            .or_else(|| self.rules.classes.get(self.rules.default_class.as_str()))
    }

    /// Decide which model should serve this request.
    ///
    /// `task_class` is the caller's `x-fuse-task-type` header (empty string
    /// if absent); an unrecognized or absent class falls back to the rules
    /// table's `default_class`. `body_len`/`max_tokens` are the same request
    /// shape [`estimate_cost`] uses, so candidates are priced exactly the way
    /// the real call will be, using this request's own I/O balance rather
    /// than an arbitrary fixed ratio.
    pub fn route(
        &self,
        requested_model: &str,
        task_class: &str,
        prices: &PriceBook,
        body_len: usize,
        max_tokens: Option<u64>,
    ) -> RouteDecision {
        let Some(rule) = self.resolve_class(task_class) else {
            return RouteDecision::kept(requested_model);
        };
        let eligible: Vec<&Candidate> = rule
            .candidates
            .iter()
            .filter(|c| c.tier >= rule.required_tier)
            .collect();
        if eligible.is_empty() {
            return RouteDecision::kept(requested_model);
        }

        let cost_of = |model: &str| -> Option<Microusd> {
            estimate_cost(prices, model, body_len, max_tokens)
        };

        // A rule explicitly requiring a higher tier than the requested model
        // is known to provide is the one case the router picks something
        // pricier than what was asked for (see the module doc). A model the
        // router has no tier opinion on is never treated as falling short.
        let must_upgrade = self
            .tier_index
            .get(requested_model)
            .is_some_and(|&t| t < rule.required_tier);

        let chosen = if must_upgrade {
            eligible
                .iter()
                .filter_map(|c| cost_of(&c.model).map(|cost| (c.model.as_str(), cost)))
                .min_by_key(|(_, cost)| *cost)
                .map(|(m, _)| m.to_string())
        } else {
            // Normal path: only ever move to something strictly cheaper than
            // what was requested. If the requested model's own cost can't be
            // determined, there is nothing to prove is cheaper, so stand pat.
            match cost_of(requested_model) {
                Some(requested_cost) => eligible
                    .iter()
                    .filter_map(|c| cost_of(&c.model).map(|cost| (c.model.as_str(), cost)))
                    .filter(|(_, cost)| *cost < requested_cost)
                    .min_by_key(|(_, cost)| *cost)
                    .map(|(m, _)| m.to_string()),
                None => None,
            }
        };

        match chosen {
            Some(model) if model != requested_model => RouteDecision {
                original_model: requested_model.to_string(),
                chosen_model: model,
            },
            _ => RouteDecision::kept(requested_model),
        }
    }
}

fn parse_rules(json: &str) -> Result<RouterRules, String> {
    serde_json::from_str(json).map_err(|e| e.to_string())
}

fn load_rules_file(path: &str) -> Result<RouterRules, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    parse_rules(&text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokenfuse_core::ModelPrice;

    /// A price book mirroring the built-in default rules' three models, plus
    /// one model the router has no tier opinion about (never declared as a
    /// candidate anywhere), priced cheaper than all three so the "never
    /// route up for an unknown model" contract has something real to prove.
    fn prices() -> PriceBook {
        PriceBook::new()
            .with(
                "claude-haiku-4-5",
                ModelPrice::per_mtok_usd(1.00, 5.00, 0.10, 1.25),
            )
            .with(
                "claude-sonnet-4-5",
                ModelPrice::per_mtok_usd(3.00, 15.00, 0.30, 3.75),
            )
            .with(
                "claude-opus-4-5",
                ModelPrice::per_mtok_usd(5.00, 25.00, 0.50, 6.25),
            )
            .with(
                "mystery-cheap-model",
                ModelPrice::per_mtok_usd(0.05, 0.05, 0.0, 0.0),
            )
    }

    fn router() -> Router {
        Router::new(RouterMode::On, default_rules())
    }

    struct Case {
        name: &'static str,
        requested: &'static str,
        task_class: &'static str,
        expected: &'static str,
    }

    /// Table-driven: (requested model, task_type header) -> expected chosen
    /// model, against the built-in default rules table.
    #[test]
    fn table_driven_routing_decisions() {
        let r = router();
        let p = prices();
        let cases = [
            Case {
                name: "opus requested for a cheap task downgrades to haiku",
                requested: "claude-opus-4-5",
                task_class: "cheap",
                expected: "claude-haiku-4-5",
            },
            Case {
                name: "sonnet requested for the default class downgrades to haiku",
                requested: "claude-sonnet-4-5",
                task_class: "default",
                expected: "claude-haiku-4-5",
            },
            Case {
                name: "haiku requested for a cheap task stays haiku",
                requested: "claude-haiku-4-5",
                task_class: "cheap",
                expected: "claude-haiku-4-5",
            },
            Case {
                name: "haiku requested for a hard task upgrades to sonnet",
                requested: "claude-haiku-4-5",
                task_class: "hard",
                expected: "claude-sonnet-4-5",
            },
            Case {
                name: "opus requested for a reasoning task downgrades to sonnet",
                requested: "claude-opus-4-5",
                task_class: "reasoning",
                expected: "claude-sonnet-4-5",
            },
            Case {
                name: "sonnet requested for a hard task stays sonnet",
                requested: "claude-sonnet-4-5",
                task_class: "hard",
                expected: "claude-sonnet-4-5",
            },
            Case {
                name: "unrecognized task class falls back to the default class",
                requested: "claude-opus-4-5",
                task_class: "some-bogus-class",
                expected: "claude-haiku-4-5",
            },
            Case {
                name: "absent task class (empty header) falls back to the default class",
                requested: "claude-opus-4-5",
                task_class: "",
                expected: "claude-haiku-4-5",
            },
            Case {
                name: "a model the router has no tier opinion on is never upgraded",
                requested: "mystery-cheap-model",
                task_class: "hard",
                expected: "mystery-cheap-model",
            },
        ];

        for case in cases {
            let decision = r.route(case.requested, case.task_class, &p, 4000, Some(1000));
            assert_eq!(decision.chosen_model, case.expected, "case: {}", case.name);
        }
    }

    #[test]
    fn never_routes_up_when_requested_is_already_cheapest_known() {
        let r = router();
        let p = prices();
        // haiku is the cheapest known model; nothing in the "cheap" class can
        // beat it, so the router must keep it, not just happen to.
        let decision = r.route("claude-haiku-4-5", "cheap", &p, 4000, Some(1000));
        assert!(!decision.routed());
        assert_eq!(decision.chosen_model, "claude-haiku-4-5");
    }

    #[test]
    fn never_routes_up_for_a_model_outside_the_rules_table() {
        let r = router();
        let p = prices();
        // "mystery-cheap-model" is priced below every candidate in the "hard"
        // class, and the router has no declared tier for it anywhere in the
        // table. A naive cost-only comparison would "upgrade" it to sonnet
        // (cheapest eligible candidate costs more); the router must not,
        // since it has no basis to claim this model falls short of the bar.
        let decision = r.route("mystery-cheap-model", "hard", &p, 4000, Some(1000));
        assert!(!decision.routed());
        assert_eq!(decision.chosen_model, "mystery-cheap-model");
    }

    #[test]
    fn explicit_higher_tier_requirement_routes_up() {
        let r = router();
        let p = prices();
        // haiku is declared Haiku-tier; the "hard" class requires Sonnet or
        // above, so this is the one case where the router pays more than
        // what was requested.
        let decision = r.route("claude-haiku-4-5", "hard", &p, 4000, Some(1000));
        assert!(decision.routed());
        assert_eq!(decision.chosen_model, "claude-sonnet-4-5");
        assert_eq!(
            decision.header_value(),
            "claude-haiku-4-5->claude-sonnet-4-5"
        );
    }

    #[test]
    fn downgrade_picks_the_cheapest_eligible_candidate_not_just_the_first() {
        let r = router();
        let p = prices();
        // opus requested for "hard": both sonnet and opus are eligible
        // (tier >= Sonnet), and both are declared cheapest-first already, but
        // the router must still pick the actually-cheaper one (sonnet) by
        // price, not just trust declaration order.
        let decision = r.route("claude-opus-4-5", "hard", &p, 4000, Some(1000));
        assert_eq!(decision.chosen_model, "claude-sonnet-4-5");
    }

    #[test]
    fn kept_decision_header_value_format() {
        let decision = RouteDecision::kept("claude-haiku-4-5");
        assert_eq!(decision.header_value(), "claude-haiku-4-5=kept");
    }

    #[test]
    fn routed_decision_header_value_format() {
        let decision = RouteDecision {
            original_model: "claude-opus-4-5".to_string(),
            chosen_model: "claude-haiku-4-5".to_string(),
        };
        assert_eq!(decision.header_value(), "claude-opus-4-5->claude-haiku-4-5");
    }

    #[test]
    fn off_mode_router_still_answers_route_when_asked_directly() {
        // `RouterMode` only gates the proxy's call site (see proxy.rs); the
        // `Router` itself has no notion of "don't compute" baked into
        // `route`, so this documents that `mode` is a proxy-side switch, not
        // part of the routing algorithm.
        let r = Router::new(RouterMode::Off, default_rules());
        let p = prices();
        let decision = r.route("claude-opus-4-5", "cheap", &p, 4000, Some(1000));
        assert_eq!(decision.chosen_model, "claude-haiku-4-5");
    }

    #[test]
    fn unknown_task_class_and_no_default_class_match_keeps_original() {
        let rules = RouterRules {
            default_class: "missing".to_string(),
            classes: HashMap::new(),
        };
        let r = Router::new(RouterMode::On, rules);
        let p = prices();
        let decision = r.route("claude-opus-4-5", "anything", &p, 4000, Some(1000));
        assert!(!decision.routed());
    }

    #[test]
    fn empty_candidates_list_keeps_original() {
        let mut classes = HashMap::new();
        classes.insert(
            "weird".to_string(),
            ClassRule {
                required_tier: Tier::Haiku,
                candidates: vec![],
            },
        );
        let rules = RouterRules {
            default_class: "weird".to_string(),
            classes,
        };
        let r = Router::new(RouterMode::On, rules);
        let p = prices();
        let decision = r.route("claude-opus-4-5", "weird", &p, 4000, Some(1000));
        assert!(!decision.routed());
    }

    #[test]
    fn parse_rules_reads_the_documented_json_shape() {
        let json = r#"{
            "default_class": "default",
            "classes": {
                "default": {
                    "required_tier": "haiku",
                    "candidates": [{"model": "claude-haiku-4-5", "tier": "haiku"}]
                },
                "hard": {
                    "required_tier": "sonnet",
                    "candidates": [
                        {"model": "claude-sonnet-4-5", "tier": "sonnet"},
                        {"model": "claude-opus-4-5", "tier": "opus"}
                    ]
                }
            }
        }"#;
        let rules = parse_rules(json).expect("valid rules json");
        assert_eq!(rules.default_class, "default");
        assert_eq!(rules.classes.len(), 2);
        assert_eq!(rules.classes["hard"].required_tier, Tier::Sonnet);
        assert_eq!(rules.classes["hard"].candidates[1].model, "claude-opus-4-5");
    }

    #[test]
    fn parse_rules_rejects_malformed_json() {
        assert!(parse_rules("not json").is_err());
    }

    #[test]
    fn load_rules_file_reads_a_custom_table_from_disk() {
        let dir = std::env::temp_dir().join(format!("tf-router-rules-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("rules.json");
        std::fs::write(
            &path,
            r#"{
                "default_class": "only",
                "classes": {
                    "only": {
                        "required_tier": "haiku",
                        "candidates": [{"model": "custom-cheap-model", "tier": "haiku"}]
                    }
                }
            }"#,
        )
        .unwrap();

        let rules = load_rules_file(path.to_str().unwrap()).expect("file loads");
        assert_eq!(rules.default_class, "only");
        assert_eq!(
            rules.classes["only"].candidates[0].model,
            "custom-cheap-model"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn load_rules_file_reports_a_missing_path() {
        assert!(load_rules_file("/nonexistent/tf-router-rules.json").is_err());
    }

    #[test]
    fn tier_ordering_is_haiku_lowest_opus_highest() {
        assert!(Tier::Haiku < Tier::Sonnet);
        assert!(Tier::Sonnet < Tier::Opus);
        assert!(Tier::Haiku < Tier::Opus);
    }
}
