//! Fuzzing property library: invariant framework + input generators.

#![allow(
    clippy::missing_docs_in_private_items,
    reason = "fuzz/test library; internal docs omitted for brevity"
)]
#![allow(
    clippy::single_char_lifetime_names,
    reason = "the `Arbitrary` trait uses `'a` and our impls must match its signature"
)]
#![allow(
    clippy::exhaustive_structs,
    reason = "fuzz-library newtype wrappers and test helpers; non_exhaustive would only add noise"
)]
#![allow(
    clippy::missing_inline_in_public_items,
    reason = "fuzz/test library; inlining hints have negligible effect here"
)]
#![allow(
    clippy::question_mark_used,
    reason = "`?` is the idiomatic Rust error-propagation operator in `Arbitrary` implementations"
)]
#![allow(
    clippy::as_conversions,
    reason = "u8 → usize for index arithmetic is safe and bounded in arbitrary contexts"
)]
#![allow(
    clippy::integer_division_remainder_used,
    reason = "modulo is the natural way to bound arbitrary u8 values to a range"
)]
#![allow(
    clippy::arbitrary_source_item_ordering,
    reason = "items are grouped logically rather than alphabetically for readability"
)]
#![allow(
    clippy::iter_over_hash_type,
    reason = "invariant checks iterate over all accounts; iteration order does not affect correctness"
)]
#![allow(
    clippy::arithmetic_side_effects,
    reason = "arithmetic is bounded by construction in test/fuzz helpers"
)]
#![allow(
    clippy::integer_division,
    reason = "u128::MAX / 2 is intentional for generating overflow-inducing test values"
)]
#![allow(
    clippy::module_name_repetitions,
    reason = "assert_invariants is the canonical, self-documenting name for this function"
)]
#![allow(
    clippy::unused_trait_names,
    reason = "named `Arbitrary` import needed to disambiguate from `proptest::arbitrary::Arbitrary` in generators.rs"
)]
#![allow(
    clippy::let_underscore_must_use,
    reason = "seed-generation IO errors are intentionally ignored in tests"
)]
#![allow(
    clippy::let_underscore_untyped,
    reason = "seed-generation IO errors are intentionally ignored in tests"
)]

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
                let _ = fs::create_dir_all(parent);
            }
            let _ = fs::write(&p, &bytes);
        }
    };
}

#[cfg(test)]
mod tests;
