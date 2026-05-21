#![cfg_attr(feature = "fuzzer-libfuzzer", no_main)]
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
//!
//! 3. **Balance conservation** — when both succeed, the sum of all known account
//!    balances (genesis ∪ diff-declared) must be identical before and after the
//!    transaction.  This catches double-credit and token-inflation bugs that both
//!    methods could agree on silently (INVARIANT 2a/2b only check consistency
//!    between the two methods, not correctness of the arithmetic itself).
//!
//! The initial state is generated from the fuzz input (rather than a fixed
//! testnet genesis) so that state-dependent bugs — those that only manifest
//! with specific account shapes such as zero balance or `u128::MAX` — are
//! reachable by the fuzzer.

use arbitrary::{Arbitrary, Unstructured};
use fuzz_props::arbitrary_types::ArbNSSATransaction;
use fuzz_props::generators::{arbitrary_fuzz_state, signer_account_ids};
use fuzz_props::invariants::{NonceSnapshot, assert_nonce_increment_correctness};
use nssa::V03State;

fuzz_props::fuzz_entry!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // Generate a fuzz-driven initial state.  The state shape — account IDs,
    // balances, and the private keys needed to sign transactions against it —
    // is fully controlled by the fuzzer, exposing state-dependent bugs that
    // the fixed testnet genesis would never reach.
    let fuzz_accs = match arbitrary_fuzz_state(&mut u) {
        Ok(accs) => accs,
        Err(_) => return,
    };
    let init_accs: Vec<(nssa::AccountId, u128)> = fuzz_accs
        .iter()
        .map(|a| (a.account_id, a.balance))
        .collect();

    // Generate the transaction from the remaining fuzz bytes.
    let tx = match ArbNSSATransaction::arbitrary(&mut u) {
        Ok(w) => w.0,
        Err(_) => return,
    };

    // Stateless gate — skip structurally malformed transactions.
    let Ok(tx) = tx.transaction_stateless_check() else { return; };

    let state = V03State::new_with_genesis_accounts(&init_accs, vec![], 0);

    // Capture nonces of all known accounts before execution so that
    // assert_nonce_increment_correctness can verify the +1 step on success.
    let nonces_before = NonceSnapshot(
        init_accs
            .iter()
            .map(|&(id, _)| (id, state.get_account_by_id(id).nonce))
            .collect(),
    );

    // validate_on_state borrows `tx` and `state` — does NOT mutate state.
    let validate_result = tx.validate_on_state(&state, 1, 0);

    // execute_check_on_state consumes `tx` and mutates `exec_state`.
    let mut exec_state = state.clone();
    let execute_result = tx.execute_check_on_state(&mut exec_state, 1, 0);

    // INVARIANT 1: both must agree on success vs failure.
    match (validate_result, execute_result) {
        (Ok(diff), Ok(applied_tx)) => {
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

            // INVARIANT 3 (balance conservation): Σ balances must be identical before and after
            // a successful transaction over all known accounts (genesis ∪ diff-declared accounts).
            //
            // This catches double-credit and token-inflation bugs that both validate_on_state and
            // execute_check_on_state could agree on silently — e.g. a transfer path that credits
            // the recipient without debiting the sender.  INVARIANT 2a/2b only check that the two
            // methods agree with each other; they do not catch the case where both are wrong in the
            // same direction.
            //
            // Limitation: accounts created brand-new by execute_check_on_state that are absent from
            // both genesis and the diff are not included here (see the known limitation in INVARIANT
            // 2b above).  A transfer to a freshly-created account would inflate the known total.
            let known_ids: std::collections::HashSet<nssa::AccountId> = init_accs
                .iter()
                .map(|&(id, _)| id)
                .chain(public_diff.keys().copied())
                .collect();
            let total_before: u128 = known_ids
                .iter()
                .map(|id| state.get_account_by_id(*id).balance)
                .fold(0u128, u128::saturating_add);
            let total_after: u128 = known_ids
                .iter()
                .map(|id| exec_state.get_account_by_id(*id).balance)
                .fold(0u128, u128::saturating_add);
            assert_eq!(
                total_before,
                total_after,
                "INVARIANT VIOLATION: total balance of known accounts changed after successful \
                 transaction (possible double-credit or token-inflation bug)",
            );

            // INVARIANT 4 (nonce increment correctness): every signer's nonce must
            // have advanced by exactly one.  This is orthogonal to the balance and
            // consistency checks above: it catches bugs where validate_on_state and
            // execute_check_on_state agree (passing INVARIANT 1) but both increment
            // the wrong account's nonce, or skip the increment entirely.
            let signer_ids = signer_account_ids(&applied_tx);
            assert_nonce_increment_correctness(&signer_ids, &nonces_before, &exec_state);
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
