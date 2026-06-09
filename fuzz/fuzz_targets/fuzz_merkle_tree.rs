#![cfg_attr(feature = "fuzzer-libfuzzer", no_main)]
//! Fuzz target: `MerkleTree` structural invariants
//!
//! Covered code paths (all in `lee/state_machine/src/merkle_tree/mod.rs`):
//!
//! ```text
//! MerkleTree::with_capacity(1)   ← initial capacity forces reallocate_to_double_capacity
//! MerkleTree::insert(value)      ← per-value; also triggers reallocate_to_double_capacity
//! MerkleTree::root()             ← sampled once after all inserts
//! MerkleTree::get_authentication_path_for(index)  ← per-value
//! prev_power_of_two              ← exercised inside reallocate_to_double_capacity
//! ```
//!
//! # Input format
//!
//! The raw fuzz bytes are sliced into 32-byte chunks; each chunk becomes one
//! value inserted into the tree.  This makes the format trivial to reason about
//! and lets us seed the corpus with well-known test vectors.
//!
//! # Invariants checked
//!
//! 1. **InsertionIndex** — `insert(value)` returns the sequential 0-based index.
//! 2. **AuthPathSome**   — `get_authentication_path_for(i)` is `Some` for every
//!    `i < length`.
//! 3. **AuthPathValid**  — every returned path re-hashes (SHA-256, same hash
//!    functions used by the production code) to the value reported by `root()`.
//! 4. **OutOfBoundsNone** — `get_authentication_path_for(length)` returns `None`.

use sha2::{Digest as _, Sha256};

// ─── Reference hash helpers (mirrors the private functions in merkle_tree/mod.rs) ───

/// SHA-256 of a single 32-byte leaf value.  Mirrors `hash_value`.
fn sha256_one(v: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(v);
    h.finalize().into()
}

/// SHA-256 of two concatenated 32-byte nodes.  Mirrors `hash_two`.
fn sha256_two(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Reference implementation of authentication-path verification.
///
/// Mirrors `verify_authentication_path` from the test module inside
/// `lee/state_machine/src/merkle_tree/mod.rs`.
///
/// Algorithm:
///   result ← SHA-256(value)
///   for each sibling in path:
///       if level_index is even → result is the LEFT child  → hash(result, sibling)
///       if level_index is odd  → result is the RIGHT child → hash(sibling, result)
///       level_index >>= 1
///   return result == root
fn verify_auth_path(value: &[u8; 32], index: usize, path: &[[u8; 32]], root: &[u8; 32]) -> bool {
    let mut result = sha256_one(value);
    let mut level_index = index;
    for sibling in path {
        let is_left_child = level_index & 1 == 0;
        result = if is_left_child {
            sha256_two(&result, sibling)
        } else {
            sha256_two(sibling, &result)
        };
        level_index >>= 1;
    }
    &result == root
}

fuzz_props::fuzz_entry!(|data: &[u8]| {
    // Treat each 32-byte chunk as one leaf value.  Discard any trailing
    // incomplete chunk.
    let values: Vec<[u8; 32]> = data
        .chunks_exact(32)
        .map(|c| c.try_into().expect("chunks_exact(32) always yields [u8;32]"))
        .collect();

    // Nothing to test with an empty input.
    if values.is_empty() {
        return;
    }

    // Start with capacity=1 so the very first pair of insertions triggers
    // `reallocate_to_double_capacity`, and each subsequent power-of-two boundary
    // triggers it again.  This exercises `prev_power_of_two`, the copy loop,
    // and the capacity / length bookkeeping inside the reallocation path.
    let mut tree = nssa::merkle_tree::MerkleTree::with_capacity(1);

    // ── INVARIANT [InsertionIndex] ────────────────────────────────────────────
    // insert() must return 0, 1, 2, … in order.
    for (expected_index, &value) in values.iter().enumerate() {
        let actual_index = tree.insert(value);
        assert_eq!(
            actual_index,
            expected_index,
            "INVARIANT VIOLATION [InsertionIndex]: \
             insert returned {actual_index} but expected {expected_index}",
        );
    }

    let root = tree.root();

    // ── INVARIANTS [AuthPathSome] and [AuthPathValid] ─────────────────────────
    for (index, value) in values.iter().enumerate() {
        let path = tree
            .get_authentication_path_for(index)
            .expect("INVARIANT VIOLATION [AuthPathSome]: \
                     get_authentication_path_for returned None for a valid index");

        assert!(
            verify_auth_path(value, index, &path, &root),
            "INVARIANT VIOLATION [AuthPathValid]: \
             authentication path for index {index} does not re-hash to root()",
        );
    }

    // ── INVARIANT [OutOfBoundsNone] ───────────────────────────────────────────
    // The index one past the last inserted element must yield None.
    assert!(
        tree.get_authentication_path_for(values.len()).is_none(),
        "INVARIANT VIOLATION [OutOfBoundsNone]: \
         get_authentication_path_for({}) should return None but returned Some",
        values.len(),
    );
});
