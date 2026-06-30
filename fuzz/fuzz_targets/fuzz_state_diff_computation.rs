#![cfg_attr(feature = "fuzzer-libfuzzer", no_main)]
//! Fuzz target: state diff isolation — bidirectional.
//!
//! Invariants:
//!
//! 1. **Forward containment** — `ValidatedStateDiff::from_public_transaction` must
//!    only produce account changes for accounts that appear in
//!    `tx.affected_public_account_ids()`.  A diff that modifies an undeclared
//!    account would allow a transaction to silently corrupt unrelated balances.
//!
//! 2. **Reverse completeness (under-reporting)** — every account declared in
//!    `tx.affected_public_account_ids()` that `execute_check_on_state` actually
//!    modifies must appear in the diff.  A diff that silently omits a balance
//!    change passes invariant 1 but leaves callers with a stale view of the state,
//!    potentially enabling double-spend and consistency bugs.
//!
//! The initial state is generated from the fuzz input (rather than a fixed
//! testnet genesis) so that state-dependent diff bugs — those triggered only by
//! specific account shapes such as zero balance or `u128::MAX` — are reachable.

use arbitrary::{Arbitrary, Unstructured};
use common::transaction::LeeTransaction;
use fuzz_props::arbitrary_types::ArbPublicTransaction;
use fuzz_props::generators::arbitrary_fuzz_state;
use nssa::ValidatedStateDiff;

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
    let state = fuzz_props::genesis::genesis_state(&init_accs, vec![]);

    // Generate the public transaction from remaining fuzz bytes.
    let pub_tx = match ArbPublicTransaction::arbitrary(&mut u) {
        Ok(w) => w.0,
        Err(_) => return,
    };

    // Collect the set of accounts the transaction declares it will touch.
    // `affected_public_account_ids()` returns owned data so `pub_tx` remains
    // available for both `from_public_transaction` (borrow) and the later move
    // into `LeeTransaction::Public`.
    let affected = pub_tx.affected_public_account_ids();

    match ValidatedStateDiff::from_public_transaction(&pub_tx, &state, 1, 0) {
        Ok(diff) => {
            let public_diff = diff.public_diff();

            // INVARIANT 1 (forward containment): every key in the diff must be
            // in `affected`.  Protects against a diff touching undeclared accounts.
            for changed_id in public_diff.keys() {
                assert!(
                    affected.contains(changed_id),
                    "INVARIANT VIOLATION: diff modified account {:?} which is not in \
                     affected_public_account_ids() {:?}",
                    changed_id,
                    affected
                );
            }

            // INVARIANT 2 (reverse completeness): every account in `affected`
            // that `execute_check_on_state` actually modifies must appear in the
            // diff.  A "silent under-report" — where execution changes an account
            // that `affected` declared but `ValidatedStateDiff` omits — passes
            // invariant 1 above but leaves the protocol with a stale state view.
            //
            // We execute the same transaction on a cloned state and compare each
            // account in `affected` before and after.  The stateless gate ensures
            // we do not panic on a structurally malformed transaction.
            let mut exec_state = state.clone();
            // `pub_tx` is moved here; it is no longer borrowed after this point.
            let tx_for_exec = LeeTransaction::Public(pub_tx);
            if let Ok(checked_tx) = tx_for_exec.transaction_stateless_check() {
                if checked_tx.execute_check_on_state(&mut exec_state, 1, 0).is_ok() {
                    for acc_id in &affected {
                        let before = state.get_account_by_id(*acc_id);
                        let after = exec_state.get_account_by_id(*acc_id);
                        if before != after {
                            assert!(
                                public_diff.contains_key(acc_id),
                                "INVARIANT VIOLATION: account {:?} is declared in \
                                 affected_public_account_ids() and was modified by \
                                 execute_check_on_state but is absent from \
                                 ValidatedStateDiff (silent under-report)",
                                acc_id
                            );
                        }
                    }
                }
            }
        }
        Err(_) => {
            // Validation failure is expected for structurally or semantically invalid inputs.
        }
    }
});
