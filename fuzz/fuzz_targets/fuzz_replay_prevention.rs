#![cfg_attr(feature = "fuzzer-libfuzzer", no_main)]
//! Fuzz target: transaction replay prevention.
//!
//! Invariant: a transaction that is accepted in block N must be rejected when
//! replayed in block N+1, because the nonce is consumed on first acceptance.
//!
//! `execute_check_on_state` returns the transaction back on success (`Ok(tx)`),
//! so we can feed the same struct to the second application without cloning.
//!
//! The initial state is generated from the fuzz input (rather than a fixed
//! testnet genesis) so that nonce-dependent edge cases — e.g. replay prevention
//! at nonce 0, nonce `u128::MAX`, or when the sender has zero balance — are
//! reachable by the fuzzer.
//!
//! # Invariants checked
//!
//! The shared framework ([`assert_invariants`]) enforces per-transaction:
//! - **StateIsolationOnFailure** — balances unchanged on rejection
//! - **BalanceConservation** — total balance conserved on success
//! - **FailedTxNonceStability** — nonces unchanged on rejection
//!
//! The dedicated [`assert_replay_rejection`] function enforces:
//! - **ReplayRejection** — accepted tx rejected on replay

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

    // Generate a fuzz-driven initial state.
    let fuzz_accs = match arbitrary_fuzz_state(&mut u) {
        Ok(accs) => accs,
        Err(_) => return,
    };
    let init_accs: Vec<(nssa::AccountId, u128)> = fuzz_accs
        .iter()
        .map(|a| (a.account_id, a.balance))
        .collect();
    let mut state = V03State::new_with_genesis_accounts(&init_accs, vec![], 0);

    // Mix correlated transactions (correctly signed, referencing a fuzz account)
    // with random ones.  Correlated transactions have a higher chance of being
    // accepted on the first application, which is necessary for the replay check
    // to fire.
    let tx_result = if bool::arbitrary(&mut u).unwrap_or(false) {
        arb_fuzz_native_transfer(&mut u, &fuzz_accs)
    } else {
        arbitrary_transaction(&mut u)
    };
    let Ok(tx) = tx_result else { return; };

    // Stateless gate: skip structurally malformed transactions.
    let Ok(tx) = tx.transaction_stateless_check() else { return; };

    // Build snapshots before execution.
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
    let state_snapshot = state.clone();

    // First application — may legitimately fail for state-level reasons.
    let result = tx.execute_check_on_state(&mut state, 1, 0);
    let execution_succeeded = result.is_ok();

    // ── Shared invariant checks ───────────────────────────────────────────────
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

    // ── NonceIncrementCorrectness + ReplayRejection ───────────────────────────
    // First verify every signer's nonce was incremented by exactly one, then
    // assert that replaying in the next block is rejected (nonce permanently consumed).
    if let Ok(applied_tx) = result {
        let signer_ids = signer_account_ids(&applied_tx);
        assert_nonce_increment_correctness(&signer_ids, &nonces_before, &state);
        assert_replay_rejection(applied_tx, &mut state, 2, 1);
    }
});
