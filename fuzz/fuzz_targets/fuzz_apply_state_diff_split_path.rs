#![no_main]
//! Fuzz target: `validate_on_state` → `apply_state_diff` split path vs
//! `execute_check_on_state` direct path.
//!
//! The following code path is covered:
//!
//! ```text
//! validate_on_state(tx, state) → diff
//! state.apply_state_diff(diff)
//! ```
//!
//! In particular, `apply_state_diff` performs a two-step operation:
//!
//! 1. Write accounts from `public_diff` into state.
//! 2. Increment nonces for every account in `signer_account_ids`.
//!
//! A bug in nonce-increment logic (wrong account ID, off-by-one, missing increment, or
//! double increment) would be caught.
//!
//! # Invariants
//!
//! 1. **SplitPathEquivalence** — for every known account (genesis ∪ diff-declared),
//!    calling `validate_on_state` followed by `apply_state_diff` must produce
//!    exactly the same account state as calling `execute_check_on_state` directly.
//!    This covers balance, nonce, data, and program_owner fields simultaneously.
//!
//! 2. **NonceIncrementCorrectness** — specifically for signer accounts, the nonce
//!    after the split path (`validate + apply`) must equal the nonce after the
//!    direct path (`execute`).  This is a stricter corollary of invariant 1 but
//!    is called out explicitly because nonce integrity is critical for replay
//!    prevention.

use std::collections::HashSet;

use arbitrary::{Arbitrary, Unstructured};
use common::transaction::NSSATransaction;
use fuzz_props::arbitrary_types::ArbNSSATransaction;
use fuzz_props::generators::arbitrary_fuzz_state;
use fuzz_props::invariants::{NonceSnapshot, assert_nonce_increment_correctness};
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

    // Generate and stateless-check a transaction.
    let tx_raw = match ArbNSSATransaction::arbitrary(&mut u) {
        Ok(w) => w.0,
        Err(_) => return,
    };
    let Ok(tx) = tx_raw.transaction_stateless_check() else {
        return;
    };

    let state = V03State::new_with_genesis_accounts(&init_accs, vec![], 0);

    // ── Split path: validate → apply ─────────────────────────────────────────
    // `validate_on_state` borrows `tx`; the transaction is still usable after.
    let validate_result = tx.validate_on_state(&state, 1, 0);

    let Ok(diff) = validate_result else {
        // validate_on_state returned Err — the direct path should also return Err.
        // (That invariant is already covered by fuzz_validate_execute_consistency.)
        return;
    };

    // ── Extract signer IDs and capture nonce snapshot before apply ────────────
    // Signer IDs are private to ValidatedStateDiff; derive them from the transaction's
    // witness set before the diff is consumed by apply_state_diff.
    let signer_ids: Vec<nssa::AccountId> = match &tx {
        NSSATransaction::Public(pub_tx) => pub_tx
            .witness_set()
            .signatures_and_public_keys()
            .iter()
            .map(|(_, pk)| nssa::AccountId::from(pk))
            .collect(),
        NSSATransaction::PrivacyPreserving(pp_tx) => pp_tx
            .witness_set()
            .signatures_and_public_keys()
            .iter()
            .map(|(_, pk)| nssa::AccountId::from(pk))
            .collect(),
        NSSATransaction::ProgramDeployment(_) => vec![],
    };
    let nonces_before = NonceSnapshot(
        signer_ids
            .iter()
            .map(|&id| (id, state.get_account_by_id(id).nonce))
            .collect(),
    );

    // Capture the IDs declared in the diff before consuming it in apply_state_diff.
    let diff_account_ids: Vec<nssa::AccountId> =
        diff.public_diff().keys().copied().collect();

    // Apply the validated diff to a clone of the original state.
    let mut split_state = state.clone();
    split_state.apply_state_diff(diff);

    // ── Standalone invariant: NonceIncrementCorrectness (split path) ──────────
    // Asserts that every signer account's nonce was incremented by exactly one,
    // catching bugs in the two-step apply_state_diff nonce-increment logic.
    assert_nonce_increment_correctness(&signer_ids, &nonces_before, &split_state);

    // ── Direct path: execute_check_on_state ───────────────────────────────────
    // This consumes `tx`; it must succeed because validate_on_state already did.
    let mut exec_state = state.clone();
    let execute_result = tx.execute_check_on_state(&mut exec_state, 1, 0);

    let Ok(_) = execute_result else {
        // Agreement between validate and execute is checked in
        // fuzz_validate_execute_consistency; we skip here to avoid duplicate noise.
        return;
    };

    // ── Invariant 1: SplitPathEquivalence ────────────────────────────────────
    // Collect all account IDs we know about: genesis accounts ∪ diff-declared.
    let all_known_ids: HashSet<nssa::AccountId> = init_accs
        .iter()
        .map(|&(id, _)| id)
        .chain(diff_account_ids.into_iter())
        .collect();

    for acc_id in &all_known_ids {
        let split_account = split_state.get_account_by_id(*acc_id);
        let exec_account = exec_state.get_account_by_id(*acc_id);

        assert_eq!(
            split_account.balance,
            exec_account.balance,
            "INVARIANT VIOLATION [SplitPathEquivalence]: balance diverges for account {:?} \
             — split path balance={} vs execute path balance={}",
            acc_id,
            split_account.balance,
            exec_account.balance,
        );

        // ── Invariant 2: NonceIncrementCorrectness ────────────────────────────
        assert_eq!(
            split_account.nonce,
            exec_account.nonce,
            "INVARIANT VIOLATION [NonceIncrementCorrectness]: nonce diverges for account {:?} \
             after validate+apply vs execute — split path nonce={:?} vs execute path nonce={:?}",
            acc_id,
            split_account.nonce,
            exec_account.nonce,
        );

        assert_eq!(
            split_account.data,
            exec_account.data,
            "INVARIANT VIOLATION [SplitPathEquivalence]: data field diverges for account {:?}",
            acc_id,
        );

        assert_eq!(
            split_account.program_owner,
            exec_account.program_owner,
            "INVARIANT VIOLATION [SplitPathEquivalence]: program_owner diverges for account {:?}",
            acc_id,
        );
    }
});
