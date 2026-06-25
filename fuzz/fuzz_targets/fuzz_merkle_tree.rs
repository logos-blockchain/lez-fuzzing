#![cfg_attr(feature = "fuzzer-libfuzzer", no_main)]
//! Fuzz target: Merkle-tree structural invariants, exercised through the
//! **public** commitment-set API (no `pub mod merkle_tree` patch required).
//!
//! The commitment set in `V03State` is a thin wrapper around the internal
//! `MerkleTree`:
//!
//! ```text
//! V03State::commitment_set_digest()        → MerkleTree::root()        (→ root_index)
//! V03State::get_proof_for_commitment(c)     → (index, MerkleTree::get_authentication_path_for(index))
//! CommitmentSet::extend(commitments)        → MerkleTree::insert(value) per commitment
//! compute_digest_for_path(c, proof)         → canonical leaf→root recomputation
//! ```
//!
//! Inserting commitments via `fuzz_props::genesis::genesis_state` therefore
//! drives `insert`, `root`/`root_index`, `get_authentication_path_for`, `depth`,
//! `get_node`/`set_node`, and — once the count exceeds the genesis capacity (32)
//! — `reallocate_to_double_capacity` and `prev_power_of_two`.
//!
//! Because the genesis commitment set has a fixed capacity of 32, a *small*
//! number of commitments exercises the partial-fill regime (`depth <
//! capacity_depth`, i.e. `root_index`'s else-branch), while a *large* number
//! (> 31) forces one or more reallocations.  A single target therefore covers
//! both regimes — the committed corpus carries a small partial-fill seed
//! (`seed_partial6`) and a large reallocation seed (`seed_realloc40`).
//!
//! # Input format
//!
//! Each 32-byte chunk of the fuzz input is reinterpreted as an `AccountId`, from
//! which a distinct `Commitment` is derived (`Commitment::new`).  Duplicate
//! chunks are dropped so every inserted commitment is unique and lands at a
//! distinct, sequential tree index.  The number of distinct chunks selects the
//! fill regime (partial-fill vs. reallocation).
//!
//! # Invariants
//!
//! 1. **ProofSome** — every inserted commitment has a membership proof.
//! 2. **ProofValid** — `compute_digest_for_path(commitment, proof)` reproduces
//!    `commitment_set_digest()` for every inserted commitment.  This is the core
//!    check: it independently recomputes the root from the leaf + authentication
//!    path and compares against the tree's reported root, catching arithmetic
//!    bugs in `root_index`, `insert`, and the path-walk.
//! 3. **IndicesSequential** — the genesis dummy commitment occupies index 0, so
//!    `N` distinct user commitments must occupy exactly indices `1..=N`.  Catches
//!    `insert -> 0` / `insert -> 1` return-value mutations.
//! 4. **NonMembershipNone** — a commitment that was never inserted has no proof.

use std::collections::HashSet;

use nssa_core::{
    Commitment, Nullifier,
    account::{Account, AccountId},
    compute_digest_for_path,
};

fuzz_props::fuzz_entry!(|data: &[u8]| {
    // Reinterpret each 32-byte chunk as an AccountId; derive one commitment each.
    // Dedup chunks so commitments are distinct and indices are clean.
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    let mut pairs: Vec<(Commitment, Nullifier)> = Vec::new();
    for chunk in data.chunks_exact(32) {
        let bytes: [u8; 32] = chunk.try_into().expect("chunks_exact(32) yields [u8;32]");
        if !seen.insert(bytes) {
            continue; // skip duplicate account ids
        }
        let commitment = Commitment::new(&AccountId::new(bytes), &Account::default());
        // A distinct nullifier per pair (content is irrelevant to the merkle tree).
        let nullifier = Nullifier::from_byte_array(bytes);
        pairs.push((commitment, nullifier));
    }

    if pairs.is_empty() {
        return;
    }

    // Keep the commitments so we can query their proofs after the state moves `pairs`.
    let commitments: Vec<Commitment> = pairs.iter().map(|(c, _)| c.clone()).collect();

    // Genesis inserts DUMMY_COMMITMENT at index 0, then our commitments at 1..=N.
    let state = fuzz_props::genesis::genesis_state(&[], pairs);
    let digest = state.commitment_set_digest();

    let mut indices: Vec<usize> = Vec::with_capacity(commitments.len());
    for commitment in &commitments {
        // ── INVARIANT [ProofSome] ─────────────────────────────────────────────
        let proof = state.get_proof_for_commitment(commitment).expect(
            "INVARIANT VIOLATION [ProofSome]: \
             get_proof_for_commitment returned None for an inserted commitment",
        );

        // ── INVARIANT [ProofValid] ────────────────────────────────────────────
        // Recompute the root from the leaf + authentication path and compare to
        // the tree's reported digest.  A bug in root_index / insert / the path
        // walk makes these disagree.
        assert_eq!(
            compute_digest_for_path(commitment, &proof),
            digest,
            "INVARIANT VIOLATION [ProofValid]: \
             membership proof for a commitment at index {} does not recompute to \
             commitment_set_digest()",
            proof.0,
        );

        indices.push(proof.0);
    }

    // ── INVARIANT [IndicesSequential] ─────────────────────────────────────────
    // The dummy commitment holds index 0; our N distinct commitments must hold
    // exactly indices 1..=N.
    indices.sort_unstable();
    for (k, &idx) in indices.iter().enumerate() {
        assert_eq!(
            idx,
            k + 1,
            "INVARIANT VIOLATION [IndicesSequential]: \
             inserted commitments must occupy sequential indices 1..=N (dummy at 0); \
             got index {idx} at sorted position {k}",
        );
    }

    // ── INVARIANT [NonMembershipNone] ─────────────────────────────────────────
    // A commitment derived from an account id that was NOT inserted must have no
    // proof.  Use an all-0xFF sentinel id and only assert when it is genuinely
    // absent from the inserted set.
    let sentinel_bytes = [0xFF_u8; 32];
    if !seen.contains(&sentinel_bytes) {
        let absent =
            Commitment::new(&AccountId::new(sentinel_bytes), &Account::default());
        assert!(
            state.get_proof_for_commitment(&absent).is_none(),
            "INVARIANT VIOLATION [NonMembershipNone]: \
             get_proof_for_commitment returned Some for a commitment never inserted",
        );
    }
});
