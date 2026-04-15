#![no_main]

use arbitrary::{Arbitrary, Unstructured};
use fuzz_props::generators::arbitrary_transaction;
use libfuzzer_sys::fuzz_target;
use nssa::V03State;
use testnet_initial_state::initial_accounts;

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // Build genesis account list from testnet initial state
    let accs_data = initial_accounts();
    let init_accs: Vec<(nssa::AccountId, u128)> = accs_data
        .iter()
        .map(|a| (a.account_id, a.balance))
        .collect();

    // Construct the initial state
    let mut state = V03State::new_with_genesis_accounts(&init_accs, vec![], 0);

    // Generate up to 8 transactions and apply them
    let n_txs: u8 = u8::arbitrary(&mut u).unwrap_or(0) % 8;
    for _ in 0..n_txs {
        let Ok(tx) = arbitrary_transaction(&mut u) else {
            break;
        };

        // Stateless gate: only attempt state transitions that pass stateless check
        let Ok(tx) = tx.transaction_stateless_check() else {
            continue;
        };

        // Clone state before to detect state leakage on failure
        let state_snapshot = state.clone();

        let block_id: u64 = 1;
        let timestamp: u64 = 0;
        let result = tx.execute_check_on_state(&mut state, block_id, timestamp);

        if result.is_err() {
            // INVARIANT: a rejected tx must leave public account balances unchanged
            for &(acc_id, _) in &init_accs {
                let bal_before = state_snapshot.get_account_by_id(acc_id).balance;
                let bal_after = state.get_account_by_id(acc_id).balance;
                assert_eq!(
                    bal_before, bal_after,
                    "INVARIANT VIOLATION: balance changed despite tx rejection for account {:?}",
                    acc_id
                );
            }
        }
    }
});
