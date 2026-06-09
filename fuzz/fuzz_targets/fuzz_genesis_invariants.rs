#![cfg_attr(feature = "fuzzer-libfuzzer", no_main)]
//! Fuzz target: genesis-state and system-account invariants.
//!
//! This target is **input-independent**: the fuzz input is always ignored.
//! It asserts deterministic invariants about the genesis state produced by
//! `V03State::new_with_genesis_accounts`, `system_faucet_account_id`,
//! `system_bridge_account_id`, and `V03State::add_pinata_token_program`.
//!
//! # Covered mutations (from `lee/state_machine/src/state.rs`)
//!
//! | Line | Mutation                                               | Assertion that catches it                           |
//! |------|--------------------------------------------------------|-----------------------------------------------------|
//! | 312  | `commitment_set_digest → Default::default()`           | `[CommitmentSetDigestNonDefault]`                   |
//! | 368  | delete `program_owner` from `add_pinata_token_program` | `[PinataTokenProgramOwner]`                         |
//! | 370  | delete `data` from `add_pinata_token_program`          | `[PinataTokenData]`                                 |
//! | 385  | `system_faucet_account → Default::default()`           | `[FaucetBalance]` + `[FaucetProgramOwner]`          |
//! | 386  | delete `program_owner` from `system_faucet_account`    | `[FaucetProgramOwner]`                              |
//! | 387  | delete `balance` from `system_faucet_account`          | `[FaucetBalance]`                                   |
//! | 393  | `system_bridge_account → Default::default()`           | `[BridgeProgramOwner]`                              |
//! | 394  | delete `program_owner` from `system_bridge_account`    | `[BridgeProgramOwner]`                              |
//! | 406  | `system_bridge_account_id → Default::default()`        | `[BridgeIdNonDefault]` + `[SystemAccountIdDistinct]` |
//!
//! # Corpus note
//!
//! A single `\x00` seed file is sufficient — the input bytes are never read.
//! The seed is required by `cargo fuzz run -runs=0` so that the replay phase
//! has at least one execution to check against.

use nssa::{Account, AccountId, V03State, system_bridge_account_id, system_faucet_account_id};

fuzz_props::fuzz_entry!(|_data: &[u8]| {
    let default_account = Account::default();

    // ── INVARIANT [BridgeIdNonDefault] ────────────────────────────────────────
    // `system_bridge_account_id()` must return a non-default `AccountId`.
    // Catches the mutation at state.rs:406 that replaces the function body with
    // `Default::default()`.
    let bridge_id = system_bridge_account_id();
    assert_ne!(
        bridge_id,
        AccountId::default(),
        "INVARIANT VIOLATION [BridgeIdNonDefault]: \
         system_bridge_account_id() must not return AccountId::default()",
    );

    // The two system account IDs must also be distinct so that they occupy
    // separate entries in the public-state map.
    let faucet_id = system_faucet_account_id();
    assert_ne!(
        faucet_id,
        bridge_id,
        "INVARIANT VIOLATION [SystemAccountIdDistinct]: \
         system_faucet_account_id() and system_bridge_account_id() must differ",
    );

    // Build the genesis state with no extra accounts.
    let state = V03State::new_with_genesis_accounts(&[], vec![], 0);

    // ── INVARIANT [FaucetBalance] ─────────────────────────────────────────────
    // The system faucet account must hold `u128::MAX` tokens.
    // Catches state.rs:385 (whole account → Default) and
    //         state.rs:387 (delete `balance` field from struct literal).
    let faucet = state.get_account_by_id(faucet_id);
    assert_eq!(
        faucet.balance,
        u128::MAX,
        "INVARIANT VIOLATION [FaucetBalance]: \
         system_faucet_account must have balance == u128::MAX, got {}",
        faucet.balance,
    );

    // ── INVARIANT [FaucetProgramOwner] ────────────────────────────────────────
    // The system faucet account must have a non-default `program_owner`.
    // Catches state.rs:385 (whole account → Default) and
    //         state.rs:386 (delete `program_owner` field from struct literal).
    assert_ne!(
        faucet.program_owner,
        default_account.program_owner,
        "INVARIANT VIOLATION [FaucetProgramOwner]: \
         system_faucet_account must have a non-default program_owner",
    );

    // ── INVARIANT [BridgeProgramOwner] ───────────────────────────────────────
    // The system bridge account must have a non-default `program_owner`.
    // Catches state.rs:393 (whole account → Default) and
    //         state.rs:394 (delete `program_owner` field from struct literal).
    let bridge = state.get_account_by_id(bridge_id);
    assert_ne!(
        bridge.program_owner,
        default_account.program_owner,
        "INVARIANT VIOLATION [BridgeProgramOwner]: \
         system_bridge_account must have a non-default program_owner",
    );

    // ── INVARIANT [CommitmentSetDigestNonDefault] ─────────────────────────────
    // A freshly created empty state has an all-zero Merkle root, which equals
    // `CommitmentSetDigest::default()`.  The genesis state inserts
    // `DUMMY_COMMITMENT` via SHA-256, producing a strictly different root.
    // Catches state.rs:312 that replaces `commitment_set_digest()` with
    // `Default::default()`.
    let empty_digest = V03State::new().commitment_set_digest();
    let genesis_digest = state.commitment_set_digest();
    assert_ne!(
        genesis_digest,
        empty_digest,
        "INVARIANT VIOLATION [CommitmentSetDigestNonDefault]: \
         commitment_set_digest of genesis state must differ from the empty state's \
         all-zero root",
    );

    // ── INVARIANT [PinataTokenProgramOwner] ──────────────────────────────────
    // An account created by `add_pinata_token_program` must have a non-default
    // `program_owner` field.
    // Catches state.rs:368 (delete `program_owner` from the struct literal).
    //
    // ── INVARIANT [PinataTokenData] ──────────────────────────────────────────
    // An account created by `add_pinata_token_program` must have non-default
    // `data` (specifically `vec![3; 33]` encoded as `Data`).
    // Catches state.rs:370 (delete `data` from the struct literal).
    let pt_id = AccountId::new([0xABu8; 32]);
    let mut pinata_state = V03State::new_with_genesis_accounts(&[], vec![], 0);
    pinata_state.add_pinata_token_program(pt_id);
    let pt = pinata_state.get_account_by_id(pt_id);

    assert_ne!(
        pt.program_owner,
        default_account.program_owner,
        "INVARIANT VIOLATION [PinataTokenProgramOwner]: \
         add_pinata_token_program must set a non-default program_owner on the account",
    );
    assert_ne!(
        pt.data,
        default_account.data,
        "INVARIANT VIOLATION [PinataTokenData]: \
         add_pinata_token_program must set non-default data on the account",
    );
});
