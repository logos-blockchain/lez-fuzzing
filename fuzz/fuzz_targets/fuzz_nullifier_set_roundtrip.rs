#![cfg_attr(feature = "fuzzer-libfuzzer", no_main)]
//! Fuzz target: `NullifierSet` Borsh serialisation.
//!
//! The `NullifierSet` has a hand-written `BorshDeserialize` (in
//! `lee/state_machine/src/state.rs`) that rejects duplicate nullifiers via
//! `if !set.insert(n)`.  This target verifies that:
//!
//! 1. States containing distinct nullifiers survive a Borsh round-trip.  The
//!    `delete-!` mutation at `state.rs:104` flips the dedup check so that
//!    `deserialize_reader` errors on the *first* (non-duplicate) element; a state
//!    with two distinct nullifiers then fails to deserialise, tripping Part 1.
//! 2. Feeding arbitrary fuzz bytes to the `V03State` deserialiser never panics.
//!
//! # Corpus note
//!
//! A single `\x00` seed is sufficient — Part 1 uses fixed inputs and catches the
//! `delete-!` mutation without fuzz-driven state.

use nssa::{Account, AccountId, V03State, system_faucet_account_id};
use nssa_core::{Commitment, Nullifier};

fuzz_props::fuzz_entry!(|data: &[u8]| {
    // ── Part 1: State with nullifiers — Borsh round-trip ─────────────────────
    // Create a V03State that contains committed nullifiers via the
    // `initial_private_accounts` constructor argument.
    //
    // With state.rs:105 mutation (delete `!`):
    // - `BorshDeserialize for NullifierSet` returns `Err` on the FIRST element
    // - `borsh::from_slice::<V03State>(&bytes)` returns Err
    // - The assert_eq below fires → mutation CAUGHT
    {
        // Two deterministic nullifier values (use from_byte_array):
        let null1 = Nullifier::from_byte_array([0xAA_u8; 32]);
        let null2 = Nullifier::from_byte_array([0xBB_u8; 32]);
        // Commitment::new takes (&AccountId, &Account):
        let comm1 = Commitment::new(&AccountId::new([0x11_u8; 32]), &Account::default());
        let comm2 = Commitment::new(&AccountId::new([0x22_u8; 32]), &Account::default());

        // Build a state that holds two nullifiers in its private state.
        let state = V03State::new_with_genesis_accounts(
            &[(system_faucet_account_id(), 0)],
            vec![(comm1, null1), (comm2, null2)],
            0,
        );

        // Serialise the state:
        let bytes = borsh::to_vec(&state)
            .expect("BorshSerialize for V03State must not fail");
        assert!(!bytes.is_empty());

        // Deserialise: with the mutation, this returns Err for any state with
        // nullifiers, triggering the assertion below.
        let state2 = borsh::from_slice::<V03State>(&bytes)
            .expect("INVARIANT VIOLATION [NullifierSetRoundtrip]: \
                     borsh::from_slice of a state with nullifiers must succeed \
                     (mutation delete-! in NullifierSet::deserialize_reader detected)");

        // Re-encode and verify idempotence:
        let bytes2 = borsh::to_vec(&state2)
            .expect("second BorshSerialize must not fail");
        assert_eq!(
            bytes,
            bytes2,
            "INVARIANT VIOLATION [NullifierSetRoundtrip]: \
             encode(decode(encode(state))) != encode(state) — \
             NullifierSet round-trip is not idempotent",
        );
    }

    // ── Part 2: Fuzz-driven raw bytes ─────────────────────────────────────────
    // Feed raw fuzz bytes through V03State deserialiser — no panic allowed.
    {
        let _ = borsh::from_slice::<V03State>(data); // NoPanic: Ok or Err, no panic
    }
});
