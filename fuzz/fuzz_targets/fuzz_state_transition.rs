#![cfg_attr(feature = "fuzzer-libfuzzer", no_main)]

use arbitrary::{Arbitrary, Unstructured};
use fuzz_props::generators::{
    arb_fuzz_native_transfer, arbitrary_fuzz_state, arbitrary_transaction, signer_account_ids,
};
use fuzz_props::invariants::{
    BalanceSnapshot, InvariantCtx, NonceSnapshot, assert_invariants,
    assert_nonce_increment_correctness, assert_replay_rejection,
};
use nssa::V03State;

fuzz_props::fuzz_entry!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // Generate a fuzz-driven initial state instead of always using the fixed
    // testnet genesis.  This exposes state-dependent bugs that only manifest
    // with specific account shapes (e.g. zero balance, u128::MAX balance, or a
    // nonce at the wrap-around boundary).
    let fuzz_accs = match arbitrary_fuzz_state(&mut u) {
        Ok(accs) => accs,
        Err(_) => return,
    };
    let init_accs: Vec<(nssa::AccountId, u128)> = fuzz_accs
        .iter()
        .map(|a| (a.account_id, a.balance))
        .collect();

    // Construct the initial state
    let mut state = V03State::new_with_genesis_accounts(&init_accs, vec![], 0);

    // Generate up to 8 transactions and apply them
    let n_txs: u8 = u8::arbitrary(&mut u).unwrap_or(0) % 8;
    for i in 0..n_txs {
        // Mix correlated transactions (referencing known fuzz accounts and
        // correctly signed) with random ones.  Correlated transactions give
        // the fuzzer a direct path to successful state transitions; random ones
        // exercise the rejection and isolation paths.
        let tx_result = if bool::arbitrary(&mut u).unwrap_or(false) {
            arb_fuzz_native_transfer(&mut u, &fuzz_accs)
        } else {
            arbitrary_transaction(&mut u)
        };
        let Ok(tx) = tx_result else {
            break;
        };

        // Stateless gate: only attempt state transitions that pass stateless check
        let Ok(tx) = tx.transaction_stateless_check() else {
            continue;
        };

        // Build snapshots from the live state before this transaction so that the
        // shared invariant framework can check isolation and conservation.
        let balances_before = BalanceSnapshot(
            init_accs
                .iter()
                .map(|&(id, _)| (id, state.get_account_by_id(id).balance))
                .collect(),
        );
        let nonces_before = NonceSnapshot(
            init_accs
                .iter()
                .map(|&(id, _)| (id, state.get_account_by_id(id).nonce))
                .collect(),
        );

        // Advance block_id and timestamp each iteration so the state machine
        // sees a realistic monotonically-increasing context.  Using the same
        // block_id=1 / timestamp=0 for every tx hides bugs that only manifest
        // when the block context changes across a multi-transaction sequence.
        let block_id: u64 = 1 + u64::from(i);
        let timestamp: u64 = u64::from(i);

        // Snapshot state before execution for isolation checks.
        let state_snapshot = state.clone();
        let result = tx.execute_check_on_state(&mut state, block_id, timestamp);
        let execution_succeeded = result.is_ok();

        // ── Shared invariant checks ───────────────────────────────────────────
        // Asserts:
        //   • StateIsolationOnFailure  — balances unchanged on rejection
        //   • BalanceConservation      — total balance conserved on success
        //   • FailedTxNonceStability   — nonces unchanged on rejection
        assert_invariants(&InvariantCtx {
            state_before: &state_snapshot,
            state_after: &state,
            execution_succeeded,
            balances_before,
            nonces_before: nonces_before.clone(),
        });

        // ── NonceIncrementCorrectness + ReplayRejection ───────────────────────
        // execute_check_on_state returns the NSSATransaction on Ok.
        // First verify every signer's nonce was incremented by exactly one, then
        // replay in the next block to confirm the nonce is permanently consumed.
        if let Ok(applied_tx) = result {
            let signer_ids = signer_account_ids(&applied_tx);
            assert_nonce_increment_correctness(&signer_ids, &nonces_before, &state);
            assert_replay_rejection(applied_tx, &mut state, block_id + 1, timestamp + 1);
        }
    }
});
