#![no_main]
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

    // First application — may legitimately fail for state-level reasons.
    let result = tx.execute_check_on_state(&mut state, 1, 0);

    if let Ok(tx) = result {
        // tx is returned on success; try applying the identical transaction again.
        let result2 = tx.execute_check_on_state(&mut state, 2, 1);
        assert!(
            result2.is_err(),
            "INVARIANT VIOLATION: transaction accepted a second time — nonce replay not prevented"
        );
    }
});
