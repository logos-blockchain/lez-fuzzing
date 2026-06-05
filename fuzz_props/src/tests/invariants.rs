use crate::generators::test_accounts;
use crate::invariants::{
    BalanceConservation, BalanceSnapshot, FailedTxNonceStability, InvariantCtx, NonceSnapshot,
    ProtocolInvariant, StateIsolationOnFailure, assert_invariants,
    assert_nonce_increment_correctness, assert_replay_rejection, assert_tx_execution_invariants,
};
use common::transaction::LeeTransaction;
use nssa::V03State;
use nssa_core::account::Nonce;

fn make_empty_state() -> V03State {
    V03State::new_with_genesis_accounts(&[], vec![], 0)
}

fn make_empty_snapshot() -> BalanceSnapshot {
    BalanceSnapshot(std::collections::HashMap::new())
}

fn make_empty_nonce_snapshot() -> NonceSnapshot {
    NonceSnapshot(std::collections::HashMap::new())
}

#[test]
fn invariant_state_isolation_on_failure_does_not_panic_on_error() {
    let state = make_empty_state();
    let ctx = InvariantCtx {
        state_before: &state,
        state_after: &state,
        execution_succeeded: false,
        balances_before: make_empty_snapshot(),
        nonces_before: make_empty_nonce_snapshot(),
    };
    assert_invariants(&ctx);
}

#[test]
fn assert_invariants_does_not_panic_on_success_with_empty_state() {
    let state = make_empty_state();
    let ctx = InvariantCtx {
        state_before: &state,
        state_after: &state,
        execution_succeeded: true,
        balances_before: make_empty_snapshot(),
        nonces_before: make_empty_nonce_snapshot(),
    };
    assert_invariants(&ctx);
}

#[test]
fn balance_conservation_catches_inflation_on_success() {
    let acc_id = nssa::AccountId::new([1_u8; 32]);
    let state_before = V03State::new_with_genesis_accounts(&[(acc_id, 100)], vec![], 0);
    let state_after = V03State::new_with_genesis_accounts(&[(acc_id, 200)], vec![], 0);

    let mut balances = std::collections::HashMap::new();
    balances.insert(acc_id, 100_u128);

    let ctx = InvariantCtx {
        state_before: &state_before,
        state_after: &state_after,
        execution_succeeded: true,
        balances_before: BalanceSnapshot(balances),
        nonces_before: make_empty_nonce_snapshot(),
    };

    let result = std::panic::catch_unwind(|| assert_invariants(&ctx));
    assert!(result.is_err(), "expected panic for balance inflation");
}

#[test]
fn nonce_increment_correctness_passes_with_no_signers() {
    let state = make_empty_state();
    assert_nonce_increment_correctness(&[], &make_empty_nonce_snapshot(), &state);
}

#[test]
fn nonce_increment_correctness_passes_when_signer_not_in_snapshot() {
    let acc_id = nssa::AccountId::new([9_u8; 32]);
    let state = make_empty_state();
    assert_nonce_increment_correctness(&[acc_id], &make_empty_nonce_snapshot(), &state);
}

#[test]
fn nonce_increment_correctness_catches_unchanged_nonce() {
    let acc_id = nssa::AccountId::new([3_u8; 32]);
    let state = V03State::new_with_genesis_accounts(&[], vec![], 0);

    let mut nonces = std::collections::HashMap::new();
    nonces.insert(acc_id, Nonce(5));

    let result = std::panic::catch_unwind(|| {
        assert_nonce_increment_correctness(&[acc_id], &NonceSnapshot(nonces), &state);
    });
    assert!(result.is_err(), "expected panic for unchanged nonce");
}

#[test]
fn failed_tx_nonce_stability_catches_nonce_mutation() {
    let acc_id = nssa::AccountId::new([2_u8; 32]);
    let state_before = V03State::new_with_genesis_accounts(&[(acc_id, 100)], vec![], 0);
    let state_after = V03State::new_with_genesis_accounts(&[(acc_id, 100)], vec![], 0);

    let mut nonces = std::collections::HashMap::new();
    nonces.insert(acc_id, Nonce(1));

    let mut balances = std::collections::HashMap::new();
    balances.insert(acc_id, 100_u128);

    let ctx = InvariantCtx {
        state_before: &state_before,
        state_after: &state_after,
        execution_succeeded: false,
        balances_before: BalanceSnapshot(balances),
        nonces_before: NonceSnapshot(nonces),
    };

    let result = std::panic::catch_unwind(|| assert_invariants(&ctx));
    assert!(
        result.is_err(),
        "expected panic for nonce mutation on failure"
    );
}

/// Verifies that `BalanceSnapshot::total` returns the correct arithmetical sum.
#[test]
fn balance_snapshot_total_is_correct_sum() {
    let mut map = std::collections::HashMap::new();
    map.insert(nssa::AccountId::new([1_u8; 32]), 100_u128);
    map.insert(nssa::AccountId::new([2_u8; 32]), 200_u128);
    map.insert(nssa::AccountId::new([3_u8; 32]), 700_u128);
    let snap = BalanceSnapshot(map);
    assert_eq!(
        snap.total(),
        1000,
        "BalanceSnapshot::total must sum all balances"
    );
}

/// Ensures `total()` is non-zero when accounts have positive balances.
///
/// Together with `balance_snapshot_total_is_correct_sum`, this forms a pair that
/// catches the `replace total with 0` mutation even when the expected sum is zero
/// in other tests.
#[test]
fn balance_snapshot_total_nonzero_for_positive_balances() {
    let mut map = std::collections::HashMap::new();
    map.insert(nssa::AccountId::new([42_u8; 32]), 1_u128);
    let snap = BalanceSnapshot(map);
    assert_ne!(
        snap.total(),
        0,
        "BalanceSnapshot::total must not return 0 when accounts have positive balances \
         (mutation: replaced with literal 0)"
    );
}

/// Verifies that `StateIsolationOnFailure::name` returns a non-empty, non-"xyzzy" string.
#[test]
fn state_isolation_name_is_nonempty_and_not_placeholder() {
    let inv = StateIsolationOnFailure;
    let name = inv.name();
    assert!(
        !name.is_empty(),
        "StateIsolationOnFailure::name must not be empty"
    );
    assert_ne!(
        name, "xyzzy",
        "StateIsolationOnFailure::name must not be 'xyzzy'"
    );
    assert_eq!(name, "StateIsolationOnFailure");
}

/// Verifies that `BalanceConservation::name` returns a non-empty, non-"xyzzy" string.
#[test]
fn balance_conservation_name_is_nonempty_and_not_placeholder() {
    let inv = BalanceConservation;
    let name = inv.name();
    assert!(
        !name.is_empty(),
        "BalanceConservation::name must not be empty"
    );
    assert_ne!(
        name, "xyzzy",
        "BalanceConservation::name must not be 'xyzzy'"
    );
    assert_eq!(name, "BalanceConservation");
}

/// Verifies that `FailedTxNonceStability::name` returns a non-empty, non-"xyzzy" string.
#[test]
fn failed_tx_nonce_stability_name_is_nonempty_and_not_placeholder() {
    let inv = FailedTxNonceStability;
    let name = inv.name();
    assert!(
        !name.is_empty(),
        "FailedTxNonceStability::name must not be empty"
    );
    assert_ne!(
        name, "xyzzy",
        "FailedTxNonceStability::name must not be 'xyzzy'"
    );
    assert_eq!(name, "FailedTxNonceStability");
}

/// Verifies that `StateIsolationOnFailure::check` returns `Some` when execution failed and
/// the balance in `state_after` differs from `balances_before`.
#[test]
fn state_isolation_check_detects_balance_change_on_failure() {
    let acc_id = nssa::AccountId::new([1_u8; 32]);
    // State has balance 100 for acc_id.
    let state = V03State::new_with_genesis_accounts(&[(acc_id, 100)], vec![], 0);

    // balances_before claims balance was 50, but state_after (== state) has 100.
    let mut balances = std::collections::HashMap::new();
    balances.insert(acc_id, 50_u128);

    let ctx = InvariantCtx {
        state_before: &state,
        state_after: &state,
        execution_succeeded: false, // failure → isolation invariant is active
        balances_before: BalanceSnapshot(balances),
        nonces_before: make_empty_nonce_snapshot(),
    };

    let inv = StateIsolationOnFailure;
    let result = inv.check(&ctx);
    assert!(
        result.is_some(),
        "StateIsolationOnFailure::check must return Some violation when \
         state_after balance (100) differs from balances_before (50) on a failed tx \
         (mutations: replace with None; delete !; replace != with ==)"
    );
}

/// Verifies that `assert_replay_rejection` panics when the replayed transaction is
/// accepted (i.e. NOT rejected — a genuine invariant violation).
#[test]
fn assert_replay_rejection_panics_when_replay_not_rejected() {
    let accounts = test_accounts();
    let (from_id, from_key) = &accounts[0];
    let (to_id, _) = &accounts[1];

    // Build a state that contains the sender account with nonce 0 and sufficient balance.
    let genesis: Vec<(nssa::AccountId, u128)> = accounts
        .iter()
        .map(|(id, _)| (*id, 10_000_000_u128))
        .collect();
    let mut state = V03State::new_with_genesis_accounts(&genesis, vec![], 0);

    // Create a valid, signed transaction with nonce 0 (the initial nonce in state).
    let tx = common::test_utils::create_transaction_native_token_transfer(
        *from_id, 0, *to_id, 100, from_key,
    );

    // We do NOT apply the tx first.  The state nonce is still 0, so calling
    // execute_check_on_state would SUCCEED — making this a "successful replay".
    // assert_replay_rejection is supposed to panic here (INVARIANT VIOLATION [ReplayRejection]).
    // block_id=0 is the genesis block; transactions are only valid from block_id=1 onwards,
    // so use (1, 0) to ensure execute_check_on_state accepts the tx (triggering the panic).
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_replay_rejection(tx, &mut state, 1, 0);
    }));

    assert!(
        result.is_err(),
        "assert_replay_rejection must panic when the replayed tx is accepted \
         (mutation: replace function body with () \u{2014} no-op skips the check)"
    );
}

/// Verifies that `assert_tx_execution_invariants` is NOT a no-op by providing a
/// context that violates `StateIsolationOnFailure` and expecting a panic.
#[test]
fn assert_tx_execution_invariants_is_not_noop() {
    let acc_id = nssa::AccountId::new([5_u8; 32]);
    // Both state_before and state_after have the account at balance 100.
    let state_before = V03State::new_with_genesis_accounts(&[(acc_id, 100)], vec![], 0);
    let mut state_after = V03State::new_with_genesis_accounts(&[(acc_id, 100)], vec![], 0);

    // Lie: claim balance was 50 before.  State_after shows 100.
    // With execution_succeeded=false, StateIsolationOnFailure detects the discrepancy.
    let mut balances = std::collections::HashMap::new();
    balances.insert(acc_id, 50_u128);

    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_tx_execution_invariants(
            &state_before,
            &mut state_after,
            BalanceSnapshot(balances),
            make_empty_nonce_snapshot(),
            Err::<LeeTransaction, &str>("simulated failure"),
            (1, 1),
        );
    }));

    assert!(
        result.is_err(),
        "assert_tx_execution_invariants must panic on a StateIsolationOnFailure violation \
         (mutation: replace entire function body with () \u{2014} no-op skips all invariant checks)"
    );
}
