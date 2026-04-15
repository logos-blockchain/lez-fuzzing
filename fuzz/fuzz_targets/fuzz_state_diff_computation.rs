#![no_main]
//! Fuzz target: state diff isolation.
//!
//! Invariant: `ValidatedStateDiff::from_public_transaction` must only produce
//! account changes for accounts that appear in `tx.affected_public_account_ids()`.
//!
//! A diff that modifies an account outside that set would allow a transaction
//! to silently corrupt unrelated accounts' balances.

use fuzz_props::arbitrary_types::ArbPublicTransaction;
use libfuzzer_sys::fuzz_target;
use nssa::{V03State, ValidatedStateDiff};
use testnet_initial_state::initial_accounts;

fuzz_target!(|wrapped: ArbPublicTransaction| {
    let pub_tx = wrapped.0;

    let accs_data = initial_accounts();
    let init_accs: Vec<(nssa::AccountId, u128)> = accs_data
        .iter()
        .map(|a| (a.account_id, a.balance))
        .collect();
    let state = V03State::new_with_genesis_accounts(&init_accs, vec![], 0);

    // Collect the set of accounts the transaction claims to touch.
    let affected = pub_tx.affected_public_account_ids();

    match ValidatedStateDiff::from_public_transaction(&pub_tx, &state, 1, 0) {
        Ok(diff) => {
            // INVARIANT: every key in the public diff must be in `affected`.
            let public_diff = diff.public_diff();
            for changed_id in public_diff.keys() {
                assert!(
                    affected.contains(changed_id),
                    "INVARIANT VIOLATION: diff modified account {:?} which is not in \
                     affected_public_account_ids() {:?}",
                    changed_id,
                    affected
                );
            }
        }
        Err(_) => {
            // Validation failure is expected for structurally or semantically invalid inputs.
        }
    }
});
