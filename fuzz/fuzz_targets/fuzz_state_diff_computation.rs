#![no_main]
//! Fuzz target: state diff isolation.
//!
//! Invariant: `ValidatedStateDiff::from_public_transaction` must only produce
//! account changes for accounts that appear in `tx.affected_public_account_ids()`.
//!
//! A diff that modifies an account outside that set would allow a transaction
//! to silently corrupt unrelated accounts' balances.
//!
//! The initial state is generated from the fuzz input (rather than a fixed
//! testnet genesis) so that state-dependent diff bugs — those triggered only by
//! specific account shapes such as zero balance or `u128::MAX` — are reachable.

use arbitrary::{Arbitrary, Unstructured};
use fuzz_props::arbitrary_types::ArbPublicTransaction;
use fuzz_props::generators::arbitrary_fuzz_state;
use libfuzzer_sys::fuzz_target;
use nssa::{V03State, ValidatedStateDiff};

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
    let state = V03State::new_with_genesis_accounts(&init_accs, vec![], 0);

    // Generate the public transaction from remaining fuzz bytes.
    let pub_tx = match ArbPublicTransaction::arbitrary(&mut u) {
        Ok(w) => w.0,
        Err(_) => return,
    };

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
