#![no_main]
//! Fuzz target: multi-block transaction sequence with long-range invariants.
//!
//! Verifies properties that span an entire *sequence* of blocks:
//!
//! - **Cumulative balance conservation**: the total balance of genesis accounts
//!   must be identical before and after ALL N blocks of transactions, even when
//!   some transactions succeed and some fail.
//!
//! - **Failed-tx nonce stability**: when a transaction is rejected, the nonce of
//!   every genesis account must remain unchanged from before that specific
//!   transaction attempt.
//!
//! - **Per-block replay rejection**: every successfully applied transaction must
//!   be rejected when replayed immediately in the next block — confirming that
//!   nonces are permanently consumed, not just temporarily blocked.
//!
//! # Invariants
//!
//! 1. **LongRangeBalanceConservation** — the total balance of the original genesis
//!    accounts is the same at the end of all N blocks as at the beginning.  Failed
//!    transactions and successful transfers between genesis accounts both preserve
//!    the total; only mint/burn bugs or token-inflation bugs would break it.
//!
//! 2. **FailedTxNonceStability** — when `execute_check_on_state` returns `Err` for
//!    a transaction, every genesis account nonce must be identical to what it was
//!    before that transaction was attempted.  Nonce mutations on failed txs would
//!    allow a griefing attack that permanently burns the victim's account.
//!
//! 3. **PerBlockReplayRejection** — every transaction that succeeded in block B is
//!    rejected when replayed in block B+1.  This is the same per-tx invariant as
//!    in `fuzz_state_transition` but exercised cumulatively across a longer
//!    sequence so that interactions between successive nonce increments are tested.

use arbitrary::{Arbitrary, Unstructured};
use fuzz_props::generators::{arb_fuzz_native_transfer, arbitrary_fuzz_state, arbitrary_transaction};
use libfuzzer_sys::fuzz_target;
use nssa::V03State;

fuzz_target!(|data: &[u8]| {
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

    // Record starting balances for the long-range conservation check (invariant 1).
    let starting_total: u128 = init_accs
        .iter()
        .map(|&(id, _)| state.get_account_by_id(id).balance)
        .fold(0u128, u128::saturating_add);

    // Apply up to 16 transactions across successive blocks.
    let n_txs: u8 = u8::arbitrary(&mut u).unwrap_or(0) % 16;

    for i in 0..n_txs {
        // Mix correlated and random transactions (same strategy as fuzz_state_transition).
        let tx_result = if bool::arbitrary(&mut u).unwrap_or(false) {
            arb_fuzz_native_transfer(&mut u, &fuzz_accs)
        } else {
            arbitrary_transaction(&mut u)
        };
        let Ok(tx_raw) = tx_result else { break };

        // Stateless gate.
        let Ok(tx) = tx_raw.transaction_stateless_check() else {
            continue;
        };

        let block_id: u64 = 1 + u64::from(i);
        let timestamp: u64 = u64::from(i) * 1000;

        // Snapshot nonces before this transaction for the nonce-stability check.
        let nonces_before: Vec<nssa_core::account::Nonce> = init_accs
            .iter()
            .map(|&(id, _)| state.get_account_by_id(id).nonce)
            .collect();

        let result = tx.execute_check_on_state(&mut state, block_id, timestamp);

        match result {
            Err(_) => {
                // ── Invariant 2: FailedTxNonceStability ──────────────────────
                for (k, &(acc_id, _)) in init_accs.iter().enumerate() {
                    let nonce_after = state.get_account_by_id(acc_id).nonce;
                    assert_eq!(
                        nonces_before[k],
                        nonce_after,
                        "INVARIANT VIOLATION [FailedTxNonceStability]: \
                         nonce changed for account {:?} after a REJECTED transaction \
                         in block {} (nonce before={:?}, nonce after={:?})",
                        acc_id,
                        block_id,
                        nonces_before[k],
                        nonce_after,
                    );
                }
            }
            Ok(applied_tx) => {
                // ── Invariant 3: PerBlockReplayRejection ─────────────────────
                let replay_result = applied_tx.execute_check_on_state(
                    &mut state,
                    block_id + 1,
                    timestamp + 1,
                );
                assert!(
                    replay_result.is_err(),
                    "INVARIANT VIOLATION [PerBlockReplayRejection]: \
                     a transaction accepted in block {} was accepted again in block {} \
                     — nonce was not consumed",
                    block_id,
                    block_id + 1,
                );
            }
        }
    }

    // ── Invariant 1: LongRangeBalanceConservation ─────────────────────────────
    // After all N blocks, the total balance of genesis accounts must equal the
    // starting total.  Successful transfers between genesis accounts cancel out;
    // failed transactions must not mutate balances (covered by
    // fuzz_state_transition's StateIsolationOnFailure, but we also verify the
    // cumulative result here to catch interactions).
    let ending_total: u128 = init_accs
        .iter()
        .map(|&(id, _)| state.get_account_by_id(id).balance)
        .fold(0u128, u128::saturating_add);

    assert_eq!(
        starting_total,
        ending_total,
        "INVARIANT VIOLATION [LongRangeBalanceConservation]: \
         total balance of genesis accounts changed after the entire transaction sequence \
         (starting total={}, ending total={}) — possible long-range token-inflation or \
         token-burn bug",
        starting_total,
        ending_total,
    );
});
