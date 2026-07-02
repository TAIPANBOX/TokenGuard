//! Semantic response cache (Ring 1.1 — "Saved this month").
//!
//! Repeated / near-repeated agent requests are answered from cache for $0. The
//! design (docs/06-semantic-cache.md) is conservative by default so a single
//! bad hit can never erode trust:
//!
//! - **Hard partition first, similarity second.** Similarity is only compared
//!   *within* an identical (model, system prompt, tools, task_type, tenant)
//!   partition — never across different system prompts.
//! - **Entity guard.** Numbers / dates / ids / emails / urls extracted from both
//!   queries must match exactly ("5 users" must not hit "50 users").
//! - **Length-ratio guard** and a high **similarity threshold** (0.97).
//! - **Shadow mode** records would-hits without serving them.
//!
//! The embedder is pluggable via [`Embedder`]. The default [`HashEmbedder`] is
//! deterministic and dependency-free (char-trigram hashing); a production ONNX
//! model (e.g. multilingual-e5-small) can drop in behind the same trait.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::hash::{Hash, Hasher};
use std::sync::Mutex;

/// Turns text into a normalized embedding vector.
pub trait Embedder: Send + Sync {
    fn embed(&self, text: &str) -> Vec<f32>;
}

/// Deterministic, dependency-free embedder: hashes character trigrams into a
/// fixed-dimension, L2-normalized vector. Good enough for "same question"
/// matching and for tests; swap in an ONNX model for production quality.
pub struct HashEmbedder {
    dim: usize,
}

impl HashEmbedder {
    pub fn new(dim: usize) -> Self {
        HashEmbedder { dim: dim.max(16) }
    }
}

impl Default for HashEmbedder {
    fn default() -> Self {
        HashEmbedder::new(256)
    }
}

impl Embedder for HashEmbedder {
    fn embed(&self, text: &str) -> Vec<f32> {
        let mut v = vec![0f32; self.dim];
        let chars: Vec<char> = text.to_lowercase().chars().collect();
        let bump = |v: &mut [f32], token: &str| {
            let mut h = std::collections::hash_map::DefaultHasher::new();
            token.hash(&mut h);
            let idx = (h.finish() as usize) % v.len();
            v[idx] += 1.0;
        };
        if chars.len() < 3 {
            bump(&mut v, &chars.iter().collect::<String>());
        } else {
            for w in chars.windows(3) {
                bump(&mut v, &w.iter().collect::<String>());
            }
        }
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for x in &mut v {
                *x /= norm;
            }
        }
        v
    }
}

/// Cosine similarity of two vectors (0 if either is zero-length).
pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() {
        return 0.0;
    }
    let dot: f32 = a.iter().zip(b).map(|(x, y)| x * y).sum();
    let na: f32 = a.iter().map(|x| x * x).sum::<f32>().sqrt();
    let nb: f32 = b.iter().map(|x| x * x).sum::<f32>().sqrt();
    if na == 0.0 || nb == 0.0 {
        0.0
    } else {
        dot / (na * nb)
    }
}

/// Extract "entities" whose exact match is required for a cache hit: whitespace
/// tokens containing a digit, an `@`, or an `http` prefix.
pub fn extract_entities(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for raw in text.split(|c: char| c.is_whitespace()) {
        let token: String = raw
            .trim_matches(|c: char| {
                !c.is_alphanumeric() && c != '@' && c != '.' && c != ':' && c != '/'
            })
            .to_lowercase();
        if token.is_empty() {
            continue;
        }
        if token.contains('@')
            || token.starts_with("http")
            || token.chars().any(|c| c.is_ascii_digit())
        {
            out.insert(token);
        }
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum CacheMode {
    #[default]
    Off,
    /// Record would-hits but never serve them.
    Shadow,
    /// Serve hits.
    On,
}

#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub mode: CacheMode,
    pub threshold: f32,
    pub ttl_millis: i64,
    pub max_per_partition: usize,
    pub entity_guard: bool,
    pub length_ratio_max: f32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            mode: CacheMode::Off,
            threshold: 0.97,
            ttl_millis: 24 * 60 * 60 * 1000, // 24h
            max_per_partition: 10_000,
            entity_guard: true,
            length_ratio_max: 1.5,
        }
    }
}

/// A cache hit: the stored response plus what it saved.
#[derive(Debug, Clone)]
pub struct Lookup {
    pub response: Vec<u8>,
    pub content_type: String,
    pub similarity: f32,
    pub saved_microusd: i64,
}

struct Entry {
    embedding: Vec<f32>,
    entities: BTreeSet<String>,
    core_len: usize,
    response: Vec<u8>,
    content_type: String,
    cost_microusd: i64,
    created_millis: i64,
}

/// A partitioned semantic cache. Cheap to share behind an `Arc`.
pub struct SemanticCache {
    embedder: Box<dyn Embedder>,
    config: CacheConfig,
    store: Mutex<HashMap<u64, Vec<Entry>>>,
}

impl SemanticCache {
    pub fn new(embedder: Box<dyn Embedder>, config: CacheConfig) -> Self {
        SemanticCache {
            embedder,
            config,
            store: Mutex::new(HashMap::new()),
        }
    }

    pub fn mode(&self) -> CacheMode {
        self.config.mode
    }

    /// Hard-partition key: similarity is only ever compared within one of these.
    pub fn partition_key(
        model: &str,
        system: &str,
        tools: &str,
        task_type: &str,
        tenant: &str,
    ) -> u64 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        model.hash(&mut h);
        system.hash(&mut h);
        tools.hash(&mut h);
        task_type.hash(&mut h);
        tenant.hash(&mut h);
        h.finish()
    }

    /// Look for a hit for `core` (the semantic core text) in `partition`.
    pub fn get(&self, partition: u64, core: &str, now_millis: i64) -> Option<Lookup> {
        if self.config.mode == CacheMode::Off {
            return None;
        }
        let query = self.embedder.embed(core);
        let entities = extract_entities(core);
        let core_len = core.chars().count();

        let mut store = self.store.lock().unwrap();
        let entries = store.get_mut(&partition)?;

        // Drop expired entries lazily.
        entries.retain(|e| now_millis - e.created_millis <= self.config.ttl_millis);

        let mut best: Option<(f32, &Entry)> = None;
        for e in entries.iter() {
            if self.config.entity_guard && e.entities != entities {
                continue;
            }
            let ratio = ratio(core_len, e.core_len);
            if ratio > self.config.length_ratio_max {
                continue;
            }
            let sim = cosine(&query, &e.embedding);
            if sim >= self.config.threshold && best.map(|(b, _)| sim > b).unwrap_or(true) {
                best = Some((sim, e));
            }
        }

        best.map(|(sim, e)| Lookup {
            response: e.response.clone(),
            content_type: e.content_type.clone(),
            similarity: sim,
            saved_microusd: e.cost_microusd,
        })
    }

    /// Store a response for future hits.
    pub fn put(
        &self,
        partition: u64,
        core: &str,
        response: Vec<u8>,
        content_type: String,
        cost_microusd: i64,
        now_millis: i64,
    ) {
        if self.config.mode == CacheMode::Off {
            return;
        }
        let entry = Entry {
            embedding: self.embedder.embed(core),
            entities: extract_entities(core),
            core_len: core.chars().count(),
            response,
            content_type,
            cost_microusd,
            created_millis: now_millis,
        };
        let mut store = self.store.lock().unwrap();
        let entries = store.entry(partition).or_default();
        entries.push(entry);
        while entries.len() > self.config.max_per_partition {
            entries.remove(0); // evict oldest (FIFO)
        }
    }
}

fn ratio(a: usize, b: usize) -> f32 {
    let (a, b) = (a.max(1) as f32, b.max(1) as f32);
    if a > b {
        a / b
    } else {
        b / a
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cache(mode: CacheMode) -> SemanticCache {
        SemanticCache::new(
            Box::new(HashEmbedder::default()),
            CacheConfig {
                mode,
                threshold: 0.9,
                ..Default::default()
            },
        )
    }

    #[test]
    fn identical_query_hits() {
        let c = cache(CacheMode::On);
        let p = SemanticCache::partition_key("m", "sys", "", "qa", "t");
        c.put(
            p,
            "how do refunds work?",
            b"cached".to_vec(),
            "application/json".into(),
            5000,
            0,
        );
        let hit = c.get(p, "how do refunds work?", 1).unwrap();
        assert_eq!(hit.response, b"cached");
        assert_eq!(hit.saved_microusd, 5000);
        assert!(hit.similarity > 0.99);
    }

    #[test]
    fn different_partition_never_hits() {
        let c = cache(CacheMode::On);
        let p1 = SemanticCache::partition_key("m", "sysA", "", "qa", "t");
        let p2 = SemanticCache::partition_key("m", "sysB", "", "qa", "t");
        c.put(p1, "hello there", b"x".to_vec(), "j".into(), 1, 0);
        assert!(c.get(p2, "hello there", 1).is_none());
    }

    #[test]
    fn entity_guard_blocks_number_mismatch() {
        let c = cache(CacheMode::On);
        let p = SemanticCache::partition_key("m", "s", "", "qa", "t");
        c.put(p, "price for 5 users", b"five".to_vec(), "j".into(), 1, 0);
        // Same words, different number → must not hit.
        assert!(c.get(p, "price for 50 users", 1).is_none());
        // Exact entity → hits.
        assert!(c.get(p, "price for 5 users", 1).is_some());
    }

    #[test]
    fn ttl_expires_entries() {
        let c = SemanticCache::new(
            Box::new(HashEmbedder::default()),
            CacheConfig {
                mode: CacheMode::On,
                threshold: 0.9,
                ttl_millis: 1000,
                ..Default::default()
            },
        );
        let p = SemanticCache::partition_key("m", "s", "", "qa", "t");
        c.put(p, "some question", b"r".to_vec(), "j".into(), 1, 0);
        assert!(c.get(p, "some question", 1000).is_some()); // within ttl
        assert!(c.get(p, "some question", 1001).is_none()); // expired
    }

    #[test]
    fn off_mode_never_stores_or_hits() {
        let c = cache(CacheMode::Off);
        let p = SemanticCache::partition_key("m", "s", "", "qa", "t");
        c.put(p, "q", b"r".to_vec(), "j".into(), 1, 0);
        assert!(c.get(p, "q", 1).is_none());
    }

    #[test]
    fn entities_extracts_numbers_emails_urls() {
        let e = extract_entities("email me at a@b.com about 42 items via https://x.io");
        assert!(e.contains("a@b.com"));
        assert!(e.contains("42"));
        assert!(e.iter().any(|t| t.starts_with("https")));
        assert!(!e.contains("items"));
    }

    #[test]
    fn cosine_bounds() {
        let a = vec![1.0, 0.0];
        let b = vec![1.0, 0.0];
        let c = vec![0.0, 1.0];
        assert!((cosine(&a, &b) - 1.0).abs() < 1e-6);
        assert!(cosine(&a, &c).abs() < 1e-6);
    }
}
