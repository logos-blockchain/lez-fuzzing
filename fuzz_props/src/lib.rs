//! Fuzzing property library: invariant framework + input generators.

#![allow(clippy::missing_docs_in_private_items)]

pub mod arbitrary_types;
pub mod generators;
pub mod invariants;

/// Generates the fuzzer entry point for whichever engine this crate is
/// compiled with, selected via Cargo features:
///
/// | Feature              | Expansion |
/// |----------------------|-----------|
/// | `fuzzer-libfuzzer`   | `libfuzzer_sys::fuzz_target!(…)` |
/// | `fuzzer-afl`         | `fn main() { afl::fuzz!(…) }` |
#[macro_export]
macro_rules! fuzz_entry {
    (|$data:ident: &[u8]| $body:block) => {
        #[cfg(feature = "fuzzer-libfuzzer")]
        ::libfuzzer_sys::fuzz_target!(|$data: &[u8]| $body);

        #[cfg(feature = "fuzzer-afl")]
        fn main() {
            ::afl::fuzz!(|$data: &[u8]| $body);
        }
    };
}

#[cfg(test)]
mod seed_gen {
    use std::fs;
    use std::path::Path;

    #[test]
    fn generate_seeds() {
        let tx = common::test_utils::produce_dummy_empty_transaction();
        let bytes = borsh::to_vec(&tx).unwrap();

        // CARGO_MANIFEST_DIR is lez-fuzzing/fuzz_props/ at compile time.
        // Tests inherit the package directory as cwd, so we must use an
        // absolute base rather than a bare relative path.
        let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("fuzz_props is one level below the workspace root");

        let targets = [
            "fuzz/corpus/fuzz_transaction_decoding/seed_empty_tx",
            "fuzz/corpus/fuzz_stateless_verification/seed_empty_tx",
            "fuzz/corpus/fuzz_state_transition/seed_empty_tx",
        ];
        for rel in &targets {
            let p = workspace_root.join(rel);
            if let Some(parent) = p.parent() {
                fs::create_dir_all(parent).ok();
            }
            fs::write(&p, &bytes).ok();
        }
    }
}
