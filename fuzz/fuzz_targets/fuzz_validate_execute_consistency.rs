#![no_main]
//! Fuzz target: `validate_on_state` and `execute_check_on_state` consistency.
//!
//! Invariants:
//!
//! 1. **Agreement** — both methods must agree on success or failure for the same
//!    transaction and state.  A divergence (one succeeds, the other fails) is a bug.
//!
//! 2. **Diff accuracy (bidirectional)** — when both succeed:
//!    - every account change recorded in the `ValidatedStateDiff` returned by
//!      `validate_on_state` must exactly match the post-execution state, AND
//!    - every account changed by `execute_check_on_state` must appear in the diff;
//!      a silent state-widening bug (execute touches an extra account not declared
//!      in the diff) is caught by the reverse check.

use fuzz_props::arbitrary_types::ArbNSSATransaction;
use libfuzzer_sys::fuzz_target;
use nssa::V03State;
use testnet_initial_state::initial_accounts;

fuzz_target!(|wrapped: ArbNSSATransaction| {
    let tx = wrapped.0;

    // Stateless gate — skip structurally malformed transactions.
    let Ok(tx) = tx.transaction_stateless_check() else { return; };

    let accs_data = initial_accounts();
    let init_accs: Vec<(nssa::AccountId, u128)> = accs_data
        .iter()
        .map(|a| (a.account_id, a.balance))
        .collect();
    let state = V03State::new_with_genesis_accounts(&init_accs, vec![], 0);

    // validate_on_state borrows `tx` and `state` — does NOT mutate state.
    let validate_result = tx.validate_on_state(&state, 1, 0);

    // execute_check_on_state consumes `tx` and mutates `exec_state`.
    let mut exec_state = state.clone();
    let execute_result = tx.execute_check_on_state(&mut exec_state, 1, 0);

    // INVARIANT 1: both must agree on success vs failure.
    match (validate_result, execute_result) {
        (Ok(diff), Ok(_)) => {
            let public_diff = diff.public_diff();

            // INVARIANT 2a (forward): every account in the diff matches the post-execute state.
            for (account_id, expected_account) in &public_diff {
                let actual = exec_state.get_account_by_id(*account_id);
                assert_eq!(
                    *expected_account,
                    actual,
                    "INVARIANT VIOLATION: validate diff and execute state disagree \
                     for account {:?}",
                    account_id
                );
            }

            // INVARIANT 2b (reverse): every account changed by execute_check_on_state must
            // be captured in the validate diff.  A silent state-widening bug — where
            // execute modifies accounts that validate_on_state did not declare — would
            // pass the forward check above but is caught here.
            //
            // We check a superset of accounts: genesis accounts PLUS any account the
            // diff explicitly declares.  This covers the common case of both mutations
            // to existing accounts and accounts the diff itself declares as new.
            //
            // Known limitation: if execute_check_on_state creates a brand-new account
            // that is absent from both the genesis set and the diff, that state-widening
            // will NOT be detected here.  Full detection would require iterating over all
            // accounts in exec_state, which V03State does not currently expose.
            let mut all_checked_ids: std::collections::HashSet<nssa::AccountId> =
                init_accs.iter().map(|&(id, _)| id).collect();
            for acc_id in public_diff.keys() {
                all_checked_ids.insert(*acc_id);
            }
            for acc_id in all_checked_ids {
                let before = state.get_account_by_id(acc_id);
                let after = exec_state.get_account_by_id(acc_id);
                if before != after {
                    assert!(
                        public_diff.contains_key(&acc_id),
                        "INVARIANT VIOLATION: execute_check_on_state modified account {:?} \
                         which is absent from validate_on_state diff",
                        acc_id
                    );
                }
            }
        }
        (Err(_), Err(_)) => {
            // Both failed — correct.
        }
        (Ok(_), Err(e)) => {
            panic!(
                "INVARIANT VIOLATION: validate_on_state succeeded but \
                 execute_check_on_state failed: {e:?}"
            );
        }
        (Err(e), Ok(_)) => {
            panic!(
                "INVARIANT VIOLATION: validate_on_state failed but \
                 execute_check_on_state succeeded: {e:?}"
            );
        }
    }
});
