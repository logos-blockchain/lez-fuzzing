#![cfg_attr(feature = "fuzzer-libfuzzer", no_main)]
//! Fuzz target: system-account modification protection.
//!
//! `LeeTransaction::validate_on_state` must reject any transaction that modifies
//! a system account (faucet, bridge, or clock accounts).  This is enforced by
//! `validate_doesnt_modify_account` which inspects `ValidatedStateDiff::public_diff()`.
//!
//! # Corpus note
//!
//! This target is **input-independent**.  A single `\x00` seed is sufficient.
//!
//! **Performance note**: the `[SystemAccountModificationRejected]` invariant
//! executes a RISC0 program (a native transfer). This is inherently slow
//! (~seconds). Only one corpus file is needed, so the corpus-regression oracle
//! costs one program execution per mutant under test.

use common::transaction::LeeTransaction;
use nssa::{
    AccountId, PrivateKey, PublicKey, V03State, ValidatedStateDiff,
    CLOCK_01_PROGRAM_ACCOUNT_ID, system_bridge_account_id, system_faucet_account_id,
};

fuzz_props::fuzz_entry!(|_data: &[u8]| {
    // ── INVARIANT [SystemAccountIdsDistinct] ──────────────────────────────────
    let faucet_id = system_faucet_account_id();
    let bridge_id = system_bridge_account_id();

    assert_ne!(
        faucet_id,
        AccountId::default(),
        "INVARIANT VIOLATION [SystemAccountIdsDistinct]: faucet account ID must be non-default",
    );
    assert_ne!(
        bridge_id,
        AccountId::default(),
        "INVARIANT VIOLATION [SystemAccountIdsDistinct]: bridge account ID must be non-default",
    );
    assert_ne!(
        faucet_id,
        bridge_id,
        "INVARIANT VIOLATION [SystemAccountIdsDistinct]: faucet and bridge must be distinct",
    );

    // ── INVARIANT [ClockInvocationRejected] ──────────────────────────────────
    // A native transfer that CREDITS a clock system account modifies exactly one
    // system account — the clock account — and that account is *changed* (its
    // balance increases from 0).  No other system account appears in the diff, so
    // this isolates the `validate_doesnt_modify_account` rejection cleanly.
    //
    // Why not a clock invocation?  The clock program writes all three clock
    // accounts, but the 01/10/50 clocks tick at different rates, so its diff
    // contains BOTH changed and unchanged system accounts.  The `!=`→`==`
    // mutation then still rejects (citing an unchanged account), so a clock
    // invocation cannot distinguish the mutant.  Crediting a single clock account
    // gives a single, changed system account, which the mutant must accept.
    //
    // Why not credit the faucet?  The faucet holds u128::MAX, so any credit
    // overflows and the program execution fails before the protection check is
    // reached.  A clock account starts at balance 0, so a small credit succeeds.
    //
    // With mutation `!=` → `==` at transaction.rs:182:
    //   The clock account is changed (post != pre), so the mutated `post == pre`
    //   check is false → no error → validate_on_state returns Ok → our assert fires.
    //
    // With mutation `public_diff → HashMap::new()` at validated_state_diff.rs:479:
    //   validate_doesnt_modify_account sees an empty map → can never find the
    //   clock account → returns Ok for every transaction → our assert fires.
    {
        let sender_key = PrivateKey::try_new([5_u8; 32]).expect("known-good key");
        let sender_pub = PublicKey::new_from_private_key(&sender_key);
        let sender_id = AccountId::from(&sender_pub);

        // Fund the sender; clock accounts already exist in genesis (balance 0).
        let state = V03State::new_with_genesis_accounts(&[(sender_id, 10_000_u128)], vec![], 0);

        // Transfer tokens TO a clock account — credits (changes) that system account.
        let tx = common::test_utils::create_transaction_native_token_transfer(
            sender_id,
            0, // nonce
            CLOCK_01_PROGRAM_ACCOUNT_ID,
            100, // amount credited to the clock account
            &sender_key,
        );

        let result = tx.validate_on_state(&state, 1, 0);

        assert!(
            result.is_err(),
            "INVARIANT VIOLATION [SystemAccountModificationRejected]: \
             validate_on_state must reject a transfer that credits a clock system \
             account.  If this fires, either validate_doesnt_modify_account has a logic \
             inversion (!=→==) or public_diff() returns an empty map",
        );
    }

    // ── INVARIANT [PublicDiffNonEmptyOnSuccess] ────────────────────────────────
    // For a valid public transaction with signers, the signer accounts must appear
    // in public_diff after successful validation (nonces are updated in the diff).
    //
    // With mutation `public_diff → HashMap::new()`:
    //   The map is empty → `contains_key(&signer)` returns false → assert fires.
    //
    // Uses `common::test_utils::create_transaction_native_token_transfer` to
    // construct a semantically valid transaction (correct instruction type).
    {
        let key = PrivateKey::try_new([7_u8; 32]).expect("known-good key");
        let pubkey = PublicKey::new_from_private_key(&key);
        let addr = AccountId::from(&pubkey);

        let key2 = PrivateKey::try_new([8_u8; 32]).expect("known-good key");
        let pubkey2 = PublicKey::new_from_private_key(&key2);
        let addr2 = AccountId::from(&pubkey2);

        let state = V03State::new_with_genesis_accounts(
            &[(addr, 10_000_u128), (addr2, 10_000_u128)],
            vec![],
            0,
        );

        // Use the test utility to build a valid native token transfer.
        // This uses the correct authenticated_transfer_core::Instruction::Transfer,
        // which the program can actually execute without panicking.
        let lee_tx = common::test_utils::create_transaction_native_token_transfer(
            addr,
            0, // nonce = 0 (matches initial state nonce)
            addr2,
            100, // amount
            &key,
        );

        if let LeeTransaction::Public(pub_tx) = &lee_tx {
            if let Ok(diff) = ValidatedStateDiff::from_public_transaction(&pub_tx, &state, 1, 0) {
                let public_diff = diff.public_diff();

                // The signer/sender (addr) must be in the diff: a native transfer
                // debits its balance, so it MUST appear in public_diff.
                // If public_diff() returns an empty HashMap, this assert fires.
                //
                // Note: nonce increments are applied separately during
                // `apply_state_diff` via `signer_account_ids` and are NOT recorded
                // in `public_diff`, so we do not assert on the nonce field here.
                assert!(
                    public_diff.contains_key(&addr),
                    "INVARIANT VIOLATION [PublicDiffNonEmptyOnSuccess]: \
                     public_diff must contain the sender {:?} (its balance is debited) \
                     after a successful native transfer \
                     (mutation public_diff→HashMap::new() detected)",
                    addr,
                );

                // The diff must reflect the balance debit on the sender — the
                // balance recorded in the diff must differ from the pre-state.
                let pre_balance = state.get_account_by_id(addr).balance;
                let post_balance = public_diff[&addr].balance;
                assert_ne!(
                    post_balance,
                    pre_balance,
                    "INVARIANT VIOLATION [PublicDiffNonEmptyOnSuccess]: \
                     sender balance in the diff must differ from pre-state after a transfer \
                     (pre={pre_balance}, post={post_balance})",
                );
            }
        }
    }
});
