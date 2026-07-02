//! WASM policies (W5): custom policy logic compiled to WebAssembly, run in a
//! `wasmtime` sandbox with a fuel limit (deterministic, bounded, safe to load
//! from anywhere — the basis for a community policy marketplace).
//!
//! ABI (scalar, stable, easy to author in any language and to test with WAT):
//! the module exports
//!
//!   `evaluate(estimate_micro: i64, spent_micro: i64, budget_micro: i64,
//!             step: i32, taint_bits: i32) -> i32`
//!
//! returning `0 = allow`, `1 = warn`, `2 = block`. `taint_bits` is a bitset
//! (web=1, file=2, secrets=4, unclassified=8). A richer JSON ABI is a future
//! extension.

/// Anything that can make a WASM-style policy decision. Kept feature-independent
/// so the gateway state has a uniform type whether or not `wasm` is compiled in.
pub trait WasmEval: Send + Sync {
    fn evaluate(
        &self,
        estimate_micro: i64,
        spent_micro: i64,
        budget_micro: i64,
        step: u32,
        taint_bits: u32,
    ) -> i32;
}

/// Taint-label bitset passed to WASM policies.
pub mod bits {
    pub const WEB: u32 = 1;
    pub const FILE: u32 = 2;
    pub const SECRETS: u32 = 4;
    pub const UNCLASSIFIED: u32 = 8;
    pub const EMAIL: u32 = 16;
}

/// Map a taint label to its bit.
pub fn label_bit(label: &str) -> u32 {
    match label {
        "web" => bits::WEB,
        "file" => bits::FILE,
        "secrets" => bits::SECRETS,
        "unclassified" => bits::UNCLASSIFIED,
        "email" => bits::EMAIL,
        _ => 0,
    }
}

#[cfg(feature = "wasm")]
pub use imp::WasmPolicy;

#[cfg(feature = "wasm")]
mod imp {
    use super::WasmEval;
    use wasmtime::{Config, Engine, Instance, Module, Store, TypedFunc};

    type EvalFn = TypedFunc<(i64, i64, i64, i32, i32), i32>;

    /// A compiled WASM policy module.
    pub struct WasmPolicy {
        engine: Engine,
        module: Module,
    }

    impl WasmPolicy {
        /// Load a policy from a `.wasm` or `.wat` file.
        pub fn from_file(path: &str) -> Result<Self, String> {
            let mut config = Config::new();
            config.consume_fuel(true);
            let engine = Engine::new(&config).map_err(|e| e.to_string())?;
            let module = Module::from_file(&engine, path).map_err(|e| e.to_string())?;
            // Validate the export exists with the right signature up front.
            {
                let mut store = Store::new(&engine, ());
                store.set_fuel(1).ok();
                let instance =
                    Instance::new(&mut store, &module, &[]).map_err(|e| e.to_string())?;
                instance
                    .get_typed_func::<(i64, i64, i64, i32, i32), i32>(&mut store, "evaluate")
                    .map_err(|e| {
                        format!("policy must export evaluate(i64,i64,i64,i32,i32)->i32: {e}")
                    })?;
            }
            Ok(WasmPolicy { engine, module })
        }

        /// Build directly from WAT/wasm bytes (used in tests).
        pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
            let mut config = Config::new();
            config.consume_fuel(true);
            let engine = Engine::new(&config).map_err(|e| e.to_string())?;
            let module = Module::new(&engine, bytes).map_err(|e| e.to_string())?;
            Ok(WasmPolicy { engine, module })
        }

        fn run(&self, args: (i64, i64, i64, i32, i32)) -> Result<i32, String> {
            let mut store = Store::new(&self.engine, ());
            // Bounded execution: a policy that loops forever runs out of fuel.
            store.set_fuel(10_000_000).map_err(|e| e.to_string())?;
            let instance =
                Instance::new(&mut store, &self.module, &[]).map_err(|e| e.to_string())?;
            let f: EvalFn = instance
                .get_typed_func(&mut store, "evaluate")
                .map_err(|e| e.to_string())?;
            f.call(&mut store, args).map_err(|e| e.to_string())
        }
    }

    impl WasmEval for WasmPolicy {
        fn evaluate(
            &self,
            estimate_micro: i64,
            spent_micro: i64,
            budget_micro: i64,
            step: u32,
            taint_bits: u32,
        ) -> i32 {
            match self.run((
                estimate_micro,
                spent_micro,
                budget_micro,
                step as i32,
                taint_bits as i32,
            )) {
                Ok(d) => d,
                // Fail-open: a broken/exhausted policy never blocks traffic.
                Err(e) => {
                    tracing::warn!("wasm policy error: {e}; allowing");
                    0
                }
            }
        }
    }
}

#[cfg(all(test, feature = "wasm"))]
mod tests {
    use super::*;

    // A policy that blocks when spent+estimate would exceed budget, OR when the
    // context is secrets-tainted (bit 4). Otherwise allow.
    const WAT: &str = r#"
    (module
      (func (export "evaluate")
        (param $est i64) (param $spent i64) (param $budget i64)
        (param $step i32) (param $taint i32) (result i32)
        ;; secrets bit set? -> block
        (if (i32.and (local.get $taint) (i32.const 4))
          (then (return (i32.const 2))))
        ;; spent + est > budget ? -> block
        (if (i64.gt_s (i64.add (local.get $spent) (local.get $est)) (local.get $budget))
          (then (return (i32.const 2))))
        (i32.const 0)))
    "#;

    fn policy() -> WasmPolicy {
        WasmPolicy::from_bytes(WAT.as_bytes()).unwrap()
    }

    #[test]
    fn allows_within_budget_and_untainted() {
        assert_eq!(policy().evaluate(1_000_000, 0, 5_000_000, 1, 0), 0);
    }

    #[test]
    fn blocks_over_budget() {
        assert_eq!(policy().evaluate(3_000_000, 3_000_000, 5_000_000, 1, 0), 2);
    }

    #[test]
    fn blocks_on_secrets_taint() {
        assert_eq!(
            policy().evaluate(1, 0, 5_000_000, 1, bits::SECRETS as i32 as u32),
            2
        );
    }

    #[test]
    fn label_bits_map() {
        assert_eq!(label_bit("secrets"), bits::SECRETS);
        assert_eq!(label_bit("nope"), 0);
    }
}
