//! Wardryx enforcement hook: a PEP (Policy Enforcement Point) for the
//! Wardryx service, a PDP (Policy Decision Point).
//!
//! TokenFuse's gateway is already the one hot-path interception point
//! between an agent and the LLM provider (ADR-4: enforcement happens before
//! forwarding). This module lets it enforce decisions Wardryx makes: before
//! a request is forwarded, the gateway asks "should this specific agent
//! action happen right now" and blocks or holds accordingly.
//!
//! This is DEFENSIVE, not offensive. It can only block or hold an
//! operator's own in-flight agent action; it never performs an action on
//! anyone's behalf.
//!
//! Wired into `proxy::messages` immediately after the custom WASM policy
//! block and before the budget `reserve()` gate (see that function for the
//! exact insertion point). `Off` (the default, and whatever
//! `TOKENFUSE_WARDRYX_URL` unset forces) is a true no-op: no allocation, no
//! network call.
//!
//! Modes:
//! - `off` (default): the hook never runs.
//! - `shadow`: always consults the PDP (subject to the cache) and reports
//!   the decision via the `x-fuse-wardryx` response header, but never blocks.
//! - `enforce`: a `deny`/`hold` decision short-circuits the request with an
//!   HTTP 403.
//!
//! `FailMode` governs what happens when the PDP can't be reached in time:
//! `open` treats an outage as `allow`, `closed` as `deny`. It only changes
//! which decision is synthesized; the mode above still decides whether that
//! decision can actually block.
//!
//! A short-TTL in-memory cache keyed by `(agent_id, sorted tool-set hash)`
//! skips the network round trip on repeat calls in a hot loop. It is a
//! simple time-based cache, not a policy_version-aware invalidation scheme;
//! a poller that proactively drops cache entries on a policy_version change
//! is a documented future enhancement, not required for this wave. `hold`
//! decisions are never cached, since a cached one would let a caller replay
//! a stale `approval_id`.
//!
//! The cache key is coarser than the full `DecideContext`: `est_cost_usd`,
//! `steps`, and `domains` all vary call to call and are deliberately NOT
//! part of the key, so a cache hit inside the TTL window reuses a decision
//! made against an earlier value of all three, not the current one. This is
//! the same known, pre-existing tradeoff the policy_version note above
//! already accepts, now also covering `max_steps`/`allow_domains`: a burst
//! of calls faster than the TTL (default 3s) can reuse an `allow` cached
//! before a step count crossed a policy's `max_steps`. Operators for whom
//! that precision matters more than the round-trip savings should lower
//! `TOKENFUSE_WARDRYX_CACHE_TTL_MS` (0 disables reuse entirely); making the
//! cache key `DecideContext`-complete is a larger change than this wave's
//! scope and would need to weigh the resulting near-zero hit rate on any
//! run past its first call, since `steps` changes on every call within it.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Default per-call timeout when `TOKENFUSE_WARDRYX_TIMEOUT_MS` is unset.
const DEFAULT_TIMEOUT_MS: u64 = 50;

/// Default decision-cache TTL when `TOKENFUSE_WARDRYX_CACHE_TTL_MS` is unset.
const DEFAULT_CACHE_TTL_MS: u64 = 3_000;

/// Operating mode, mirroring the off/shadow/enforce convention already used
/// by `TOKENFUSE_FIREWALL`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum WardryxMode {
    #[default]
    Off,
    Shadow,
    Enforce,
}

/// What to do when the PDP can't be reached (timeout or transport error)
/// before this call's deadline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailMode {
    /// Treat an unreachable PDP as `allow`: the request proceeds.
    #[default]
    Open,
    /// Treat an unreachable PDP as `deny`: the request is blocked.
    Closed,
}

/// One decision from the PDP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WardryxDecision {
    Allow,
    Deny,
    Hold,
}

impl WardryxDecision {
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "allow" => Some(WardryxDecision::Allow),
            "deny" => Some(WardryxDecision::Deny),
            "hold" => Some(WardryxDecision::Hold),
            _ => None,
        }
    }

    /// The `x-fuse-wardryx` response header value for this decision (used
    /// both bare, in enforce mode, and as the `would-<decision>` suffix in
    /// shadow mode).
    pub fn as_wire_str(&self) -> &'static str {
        match self {
            WardryxDecision::Allow => "allow",
            WardryxDecision::Deny => "deny",
            WardryxDecision::Hold => "hold",
        }
    }
}

/// The full result of a `decide` call: what to do, plus everything a block
/// response needs in order to explain itself to the caller.
#[derive(Debug, Clone)]
pub struct WardryxOutcome {
    pub decision: WardryxDecision,
    pub policy_version: Option<String>,
    pub reason: Option<String>,
    /// Set only on `hold`: the id the caller references, via
    /// `x-fuse-approval-token` once approved, to resubmit the request.
    pub approval_id: Option<String>,
    /// Whether resubmission requires `x-fuse-approval-token`. Defaults to
    /// `true` (the safer assumption) when the PDP response omits it.
    pub approval_token_required: bool,
}

/// Everything `Wardryx::decide` needs: the caller (`proxy::messages`)
/// gathers this up front from request context already in scope at the
/// insertion point, so `decide` itself stays a single, easy-to-read call.
pub struct DecideContext {
    pub agent_id: String,
    pub run_id: String,
    pub on_behalf_of: Vec<String>,
    pub tool_names: Vec<String>,
    /// The run's accumulated step count *before* this action, i.e.
    /// `snapshot.steps` at the insertion point: how many prior actions on
    /// this run have already been reserved. Checked by Wardryx against a
    /// matched policy's `max_steps`; once this reaches or exceeds that cap,
    /// Wardryx denies. Zero for a run's first action.
    pub steps: u32,
    /// Best-effort domains this action's declared tools reference (see
    /// `proxy::referenced_domains`). Empty for a plain LLM call with no
    /// URL-bearing tools, which Wardryx treats as "nothing declared to
    /// restrict," never as a denial.
    pub domains: Vec<String>,
    pub model: String,
    pub est_cost_usd: f64,
    pub attestation_method: Option<String>,
    pub approval_token: Option<String>,
}

#[derive(Debug, Serialize)]
struct DecideWireRequest<'a> {
    agent_id: &'a str,
    run_id: &'a str,
    on_behalf_of: &'a [String],
    tool_names: &'a [String],
    domains: &'a [String],
    steps: u32,
    model: &'a str,
    est_cost_usd: f64,
    attestation_method: Option<&'a str>,
    approval_token: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
struct DecideWireResponse {
    decision: String,
    #[serde(default)]
    policy_version: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    approval_id: Option<String>,
    #[serde(default)]
    approval_token_required: Option<bool>,
}

#[derive(Debug, thiserror::Error)]
enum WardryxError {
    #[error("wardryx request failed: {0}")]
    Transport(String),
    #[error("wardryx response was not valid JSON: {0}")]
    Decode(String),
    #[error("wardryx returned an unrecognized decision: {0}")]
    UnknownDecision(String),
}

/// Talks to the Wardryx `POST {base_url}/v1/decide` endpoint. Kept separate
/// from [`Wardryx`] (the mode/failmode/cache bundle) so the HTTP concern and
/// the policy concern stay independently readable and testable.
struct WardryxClient {
    http: reqwest::Client,
    base_url: String,
    key: Option<String>,
    timeout: Duration,
}

impl WardryxClient {
    fn new(base_url: impl Into<String>, key: Option<String>, timeout: Duration) -> Self {
        WardryxClient {
            http: reqwest::Client::new(),
            base_url: base_url.into(),
            key,
            timeout,
        }
    }

    async fn decide(&self, req: &DecideWireRequest<'_>) -> Result<WardryxOutcome, WardryxError> {
        let endpoint = format!("{}/v1/decide", self.base_url.trim_end_matches('/'));
        let payload = serde_json::to_vec(req).map_err(|e| WardryxError::Decode(e.to_string()))?;
        let mut builder = self
            .http
            .post(&endpoint)
            .timeout(self.timeout)
            .header("content-type", "application/json")
            .body(payload);
        if let Some(key) = &self.key {
            if !key.is_empty() {
                builder = builder.bearer_auth(key);
            }
        }
        let resp = builder
            .send()
            .await
            .map_err(|e| WardryxError::Transport(e.to_string()))?;
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| WardryxError::Transport(e.to_string()))?;
        let wire: DecideWireResponse =
            serde_json::from_slice(&bytes).map_err(|e| WardryxError::Decode(e.to_string()))?;
        let decision = WardryxDecision::parse(&wire.decision)
            .ok_or(WardryxError::UnknownDecision(wire.decision))?;
        Ok(WardryxOutcome {
            decision,
            policy_version: wire.policy_version,
            reason: wire.reason,
            approval_id: wire.approval_id,
            approval_token_required: wire.approval_token_required.unwrap_or(true),
        })
    }
}

/// One cached decision.
#[derive(Debug, Clone)]
struct CacheEntry {
    decision: WardryxDecision,
    policy_version: Option<String>,
    reason: Option<String>,
    cached_at: Instant,
}

/// Short-TTL in-memory decision cache keyed by `(agent_id, sorted tool-set
/// hash)`. See the module doc for why `hold` is never cached.
struct Cache {
    ttl: Duration,
    entries: Mutex<HashMap<(String, u64), CacheEntry>>,
}

impl Cache {
    fn new(ttl: Duration) -> Self {
        Cache {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    fn key(agent_id: &str, tool_names: &[String]) -> (String, u64) {
        let mut sorted: Vec<&str> = tool_names.iter().map(String::as_str).collect();
        sorted.sort_unstable();
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        sorted.hash(&mut hasher);
        (agent_id.to_string(), hasher.finish())
    }

    fn get(&self, agent_id: &str, tool_names: &[String]) -> Option<WardryxOutcome> {
        let key = Self::key(agent_id, tool_names);
        let entries = self.entries.lock().unwrap();
        let entry = entries.get(&key)?;
        if entry.cached_at.elapsed() >= self.ttl {
            return None;
        }
        Some(WardryxOutcome {
            decision: entry.decision,
            policy_version: entry.policy_version.clone(),
            reason: entry.reason.clone(),
            // Only `allow`/`deny` are ever stored (see `put`), and neither
            // carries an approval id, so this is always correct for a hit.
            approval_id: None,
            approval_token_required: true,
        })
    }

    fn put(&self, agent_id: &str, tool_names: &[String], outcome: &WardryxOutcome) {
        // Never cache `hold`: a replayed hit would hand out a stale
        // `approval_id` for what looks like a fresh hold.
        if outcome.decision == WardryxDecision::Hold {
            return;
        }
        let key = Self::key(agent_id, tool_names);
        let entry = CacheEntry {
            decision: outcome.decision,
            policy_version: outcome.policy_version.clone(),
            reason: outcome.reason.clone(),
            cached_at: Instant::now(),
        };
        self.entries.lock().unwrap().insert(key, entry);
    }
}

/// The Wardryx hook: mode, fail-open/closed behavior, the HTTP client
/// (absent when disabled), and the decision cache. Bundled the same way
/// [`crate::router::Router`] bundles the model router's mode/rules/index.
pub struct Wardryx {
    pub mode: WardryxMode,
    failmode: FailMode,
    client: Option<WardryxClient>,
    cache: Cache,
}

impl Wardryx {
    /// Off, no client configured. `AppState`'s starting point before
    /// `serve()` calls `from_env`.
    pub fn disabled() -> Self {
        Wardryx {
            mode: WardryxMode::Off,
            failmode: FailMode::Open,
            client: None,
            cache: Cache::new(Duration::from_millis(DEFAULT_CACHE_TTL_MS)),
        }
    }

    /// Build directly from explicit settings (used by `from_env` and by
    /// tests that point the client at a stub server rather than going
    /// through environment variables).
    pub fn new(
        mode: WardryxMode,
        failmode: FailMode,
        base_url: impl Into<String>,
        key: Option<String>,
        timeout: Duration,
        cache_ttl: Duration,
    ) -> Self {
        Wardryx {
            mode,
            failmode,
            client: Some(WardryxClient::new(base_url, key, timeout)),
            cache: Cache::new(cache_ttl),
        }
    }

    /// Build from `TOKENFUSE_WARDRYX_*` env (see the module doc for the
    /// full list). A missing/empty `TOKENFUSE_WARDRYX_URL` forces `Off`
    /// regardless of `TOKENFUSE_WARDRYX_MODE`: with nothing to call there is
    /// nothing to enforce or shadow.
    pub fn from_env() -> Self {
        let requested_mode = match std::env::var("TOKENFUSE_WARDRYX_MODE").as_deref() {
            Ok("shadow") => WardryxMode::Shadow,
            Ok("enforce") => WardryxMode::Enforce,
            _ => WardryxMode::Off,
        };
        let url = std::env::var("TOKENFUSE_WARDRYX_URL")
            .ok()
            .filter(|s| !s.is_empty());
        let Some(url) = url else {
            if requested_mode != WardryxMode::Off {
                tracing::warn!(
                    "TOKENFUSE_WARDRYX_MODE is set but TOKENFUSE_WARDRYX_URL is not; \
                     the wardryx hook stays off"
                );
            }
            return Wardryx::disabled();
        };

        let failmode = match std::env::var("TOKENFUSE_WARDRYX_FAILMODE").as_deref() {
            Ok("closed") => FailMode::Closed,
            _ => FailMode::Open,
        };
        let key = std::env::var("TOKENFUSE_WARDRYX_KEY")
            .ok()
            .filter(|s| !s.is_empty());
        let timeout_ms: u64 = std::env::var("TOKENFUSE_WARDRYX_TIMEOUT_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_TIMEOUT_MS);
        let cache_ttl_ms: u64 = std::env::var("TOKENFUSE_WARDRYX_CACHE_TTL_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_CACHE_TTL_MS);

        Wardryx::new(
            requested_mode,
            failmode,
            url,
            key,
            Duration::from_millis(timeout_ms),
            Duration::from_millis(cache_ttl_ms),
        )
    }

    /// Ask the PDP (or the cache) what to do about this call. Always
    /// returns an outcome: transport/timeout/decode failures are absorbed
    /// here via `failmode`, never surfaced as a `Result` to the caller.
    /// Only meant to be called when `mode != Off` (see `proxy::messages`);
    /// `client` is guaranteed `Some` whenever that holds (see `from_env`),
    /// but a missing client still fails safe via `failmode` rather than
    /// panicking, in case a future caller changes that invariant.
    pub async fn decide(&self, ctx: DecideContext) -> WardryxOutcome {
        if let Some(cached) = self.cache.get(&ctx.agent_id, &ctx.tool_names) {
            return cached;
        }
        let Some(client) = &self.client else {
            return self.fallback("wardryx hook has no client configured");
        };

        let wire = DecideWireRequest {
            agent_id: &ctx.agent_id,
            run_id: &ctx.run_id,
            on_behalf_of: &ctx.on_behalf_of,
            tool_names: &ctx.tool_names,
            domains: &ctx.domains,
            steps: ctx.steps,
            model: &ctx.model,
            est_cost_usd: ctx.est_cost_usd,
            attestation_method: ctx.attestation_method.as_deref(),
            approval_token: ctx.approval_token.as_deref(),
        };
        match client.decide(&wire).await {
            Ok(outcome) => {
                self.cache.put(&ctx.agent_id, &ctx.tool_names, &outcome);
                outcome
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    failmode = ?self.failmode,
                    "wardryx decide call failed; applying failmode"
                );
                self.fallback(&e.to_string())
            }
        }
    }

    /// Synthesize an outcome for "the PDP could not be reached", per
    /// `failmode`. Never cached: a transient outage should not stick around
    /// for the cache TTL once the PDP recovers.
    fn fallback(&self, detail: &str) -> WardryxOutcome {
        let decision = match self.failmode {
            FailMode::Open => WardryxDecision::Allow,
            FailMode::Closed => WardryxDecision::Deny,
        };
        WardryxOutcome {
            decision,
            policy_version: None,
            reason: Some(format!(
                "wardryx unreachable ({detail}); failmode={:?} applied",
                self.failmode
            )),
            approval_id: None,
            approval_token_required: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_parses_case_insensitively() {
        assert_eq!(
            WardryxDecision::parse("Allow"),
            Some(WardryxDecision::Allow)
        );
        assert_eq!(WardryxDecision::parse("DENY"), Some(WardryxDecision::Deny));
        assert_eq!(WardryxDecision::parse("hold"), Some(WardryxDecision::Hold));
        assert_eq!(WardryxDecision::parse("bogus"), None);
    }

    #[test]
    fn cache_key_is_order_independent() {
        let a = Cache::key("agent-1", &["b".to_string(), "a".to_string()]);
        let b = Cache::key("agent-1", &["a".to_string(), "b".to_string()]);
        assert_eq!(a, b, "tool order must not change the cache key");
    }

    #[test]
    fn cache_key_differs_by_agent() {
        let a = Cache::key("agent-1", &["a".to_string()]);
        let b = Cache::key("agent-2", &["a".to_string()]);
        assert_ne!(a, b);
    }

    #[test]
    fn cache_round_trips_allow_and_deny() {
        let cache = Cache::new(Duration::from_secs(60));
        let outcome = WardryxOutcome {
            decision: WardryxDecision::Deny,
            policy_version: Some("v1".to_string()),
            reason: Some("no".to_string()),
            approval_id: None,
            approval_token_required: true,
        };
        cache.put("agent-1", &["grep".to_string()], &outcome);
        let hit = cache.get("agent-1", &["grep".to_string()]).unwrap();
        assert_eq!(hit.decision, WardryxDecision::Deny);
        assert_eq!(hit.policy_version.as_deref(), Some("v1"));
    }

    #[test]
    fn cache_never_stores_hold() {
        let cache = Cache::new(Duration::from_secs(60));
        let outcome = WardryxOutcome {
            decision: WardryxDecision::Hold,
            policy_version: None,
            reason: None,
            approval_id: Some("appr-1".to_string()),
            approval_token_required: true,
        };
        cache.put("agent-1", &["grep".to_string()], &outcome);
        assert!(cache.get("agent-1", &["grep".to_string()]).is_none());
    }

    #[test]
    fn cache_expires_after_ttl() {
        let cache = Cache::new(Duration::from_millis(1));
        let outcome = WardryxOutcome {
            decision: WardryxDecision::Allow,
            policy_version: None,
            reason: None,
            approval_id: None,
            approval_token_required: true,
        };
        cache.put("agent-1", &["grep".to_string()], &outcome);
        std::thread::sleep(Duration::from_millis(20));
        assert!(cache.get("agent-1", &["grep".to_string()]).is_none());
    }

    #[tokio::test]
    async fn from_env_stays_off_without_a_url() {
        std::env::remove_var("TOKENFUSE_WARDRYX_URL");
        std::env::set_var("TOKENFUSE_WARDRYX_MODE", "enforce");
        let w = Wardryx::from_env();
        assert_eq!(w.mode, WardryxMode::Off);
        std::env::remove_var("TOKENFUSE_WARDRYX_MODE");
    }

    #[tokio::test]
    async fn decide_fails_open_with_no_client_configured() {
        let w = Wardryx::disabled();
        let outcome = w
            .decide(DecideContext {
                agent_id: "a".into(),
                run_id: "r".into(),
                on_behalf_of: vec![],
                tool_names: vec![],
                domains: vec![],
                steps: 0,
                model: "m".into(),
                est_cost_usd: 0.0,
                attestation_method: None,
                approval_token: None,
            })
            .await;
        assert_eq!(outcome.decision, WardryxDecision::Allow);
    }

    #[tokio::test]
    async fn decide_fails_closed_with_no_client_configured_when_requested() {
        let mut w = Wardryx::disabled();
        w.failmode = FailMode::Closed;
        let outcome = w
            .decide(DecideContext {
                agent_id: "a".into(),
                run_id: "r".into(),
                on_behalf_of: vec![],
                tool_names: vec![],
                domains: vec![],
                steps: 0,
                model: "m".into(),
                est_cost_usd: 0.0,
                attestation_method: None,
                approval_token: None,
            })
            .await;
        assert_eq!(outcome.decision, WardryxDecision::Deny);
    }
}
