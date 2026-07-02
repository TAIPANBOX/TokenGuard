//! Embedder selection for the semantic cache.
//!
//! The default is the dependency-free [`HashEmbedder`]. Build with
//! `--features onnx` and set `TOKENFUSE_CACHE_EMBEDDER=onnx` to use a real
//! sentence-embedding model (multilingual-e5-small) via `fastembed`, which
//! downloads the model on first use. CI builds the default (no `onnx`) so it
//! stays fast and offline.

use tokenfuse_core::cache::{Embedder, HashEmbedder};

/// Build the embedder for the cache based on features and `TOKENFUSE_CACHE_EMBEDDER`.
pub fn build() -> Box<dyn Embedder> {
    #[cfg(feature = "onnx")]
    {
        if matches!(
            std::env::var("TOKENFUSE_CACHE_EMBEDDER").as_deref(),
            Ok("onnx")
        ) {
            match onnx::OnnxEmbedder::new() {
                Ok(e) => {
                    tracing::info!("cache embedder: ONNX multilingual-e5-small");
                    return Box::new(e);
                }
                Err(e) => tracing::warn!("ONNX embedder init failed ({e}); using hash embedder"),
            }
        }
    }
    Box::new(HashEmbedder::default())
}

#[cfg(feature = "onnx")]
mod onnx {
    use fastembed::{EmbeddingModel, InitOptions, TextEmbedding};
    use std::sync::Mutex;
    use tokenfuse_core::cache::Embedder;

    /// Real sentence embeddings via `fastembed` (ONNX Runtime). The model is
    /// downloaded and cached on first construction.
    pub struct OnnxEmbedder {
        model: Mutex<TextEmbedding>,
    }

    impl OnnxEmbedder {
        pub fn new() -> Result<Self, String> {
            let model =
                TextEmbedding::try_new(InitOptions::new(EmbeddingModel::MultilingualE5Small))
                    .map_err(|e| e.to_string())?;
            Ok(OnnxEmbedder {
                model: Mutex::new(model),
            })
        }
    }

    impl Embedder for OnnxEmbedder {
        fn embed(&self, text: &str) -> Vec<f32> {
            let mut v = self
                .model
                .lock()
                .unwrap()
                .embed(vec![text], None)
                .ok()
                .and_then(|mut batch| batch.pop())
                .unwrap_or_default();
            // Normalize so cosine behaves consistently with the hash embedder.
            let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
            if norm > 0.0 {
                for x in &mut v {
                    *x /= norm;
                }
            }
            v
        }
    }
}
