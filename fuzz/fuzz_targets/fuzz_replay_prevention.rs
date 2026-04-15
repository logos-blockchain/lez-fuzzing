#![no_main]
//! Fuzz target: transaction replay prevention.
//!
//! Invariant: a transaction that is accepted in block N must be rejected when
//! replayed in block N+1, because the nonce is consumed on first acceptance.
//!
//! `execute_check_on_state` returns the transaction back on success (`Ok(tx)`),
//! so we can feed the same struct to the second application without cloning.

use arbitrary::Unstructured;
use fuzz_props::generators::arbitrary_transaction;
use libfuzzer_sys::fuzz_target;
use nssa::V03State;
use testnet_initial_state::initial_accounts;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    let accs_data = initial_accounts();
    let init_accs: Vec<(nssa::AccountId, u128)> = accs_data
        .iter()
        .map(|a| (a.account_id, a.balance))
        .collect();
    let mut state = V03State::new_with_genesis_accounts(&init_accs, vec![], 0);

    let Ok(tx) = arbitrary_transaction(&mut u) else { return; };

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
