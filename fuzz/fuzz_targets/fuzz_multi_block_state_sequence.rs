#![cfg_attr(feature = "fuzzer-libfuzzer", no_main)]
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
//! The following per-transaction invariants are checked via
//! [`fuzz_props::invariants::assert_tx_execution_invariants`] on every iteration:
//!
//! - **StateIsolationOnFailure** — balances unchanged on rejection.
//! - **FailedTxNonceStability** — nonces unchanged on rejection.
//! - **BalanceConservation** — total balance conserved on success.
//! - **NonceIncrementCorrectness** — signer nonces each increment by exactly one on success.
//! - **ReplayRejection** — every successful transaction rejected on replay (per-block).
//!
//! The following multi-block aggregate invariant is checked **after** the loop:
//!
//! 1. **LongRangeBalanceConservation** — the total balance of the original genesis
//!    accounts is the same at the end of all N blocks as at the beginning.  Failed
//!    transactions and successful transfers between genesis accounts both preserve
//!    the total; only mint/burn bugs or token-inflation bugs would break it.

use arbitrary::{Arbitrary, Unstructured};
use fuzz_props::generators::{arb_fuzz_native_transfer, arbitrary_fuzz_state, arbitrary_transaction};
use fuzz_props::invariants::{BalanceSnapshot, NonceSnapshot, assert_tx_execution_invariants};

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

    let mut state = fuzz_props::genesis::genesis_state(&init_accs, vec![]);

    // Record starting balances for the long-range conservation check.
    let starting_total: u128 = init_accs
        .iter()
        .map(|&(id, _)| state.get_account_by_id(id).balance)
        .try_fold(0u128, |acc, x| acc.checked_add(x))
        .expect(
            "INVARIANT VIOLATION [BalanceOverflow]: initial sum of genesis account balances \
             exceeded u128::MAX — per-account balance cap in arbitrary_fuzz_state() should \
             prevent this; if triggered, the cap has been raised without updating this check",
        );

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

        // Build per-transaction snapshots for the shared invariant framework.
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

        let result = tx.execute_check_on_state(&mut state, block_id, timestamp);

        // ── All five protocol invariants ──────────────────────────────────────
        // A single call enforces every invariant — no standalone helpers needed:
        //   On rejection: StateIsolationOnFailure + FailedTxNonceStability
        //   On success:   BalanceConservation + NonceIncrementCorrectness + ReplayRejection
        assert_tx_execution_invariants(
            &state_snapshot,
            &mut state,
            balances_before,
            nonces_before,
            result,
            (block_id + 1, timestamp + 1),
        );
    }

    // ── LongRangeBalanceConservation ──────────────────────────────────────────
    // After all N blocks, the total balance of genesis accounts must equal the
    // starting total.  Successful transfers between genesis accounts cancel out;
    // failed transactions must not mutate balances (covered per-tx by
    // StateIsolationOnFailure above, verified cumulatively here to catch
    // interactions across the full sequence).
    let ending_total: u128 = init_accs
        .iter()
        .map(|&(id, _)| state.get_account_by_id(id).balance)
        .try_fold(0u128, |acc, x| acc.checked_add(x))
        .expect(
            "INVARIANT VIOLATION [BalanceOverflow]: final sum of genesis account balances \
             exceeded u128::MAX — token-inflation bug that saturating_add would have \
             silently masked",
        );

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
