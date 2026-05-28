use crate::invariants::{
    BalanceSnapshot, InvariantCtx, NonceSnapshot, assert_invariants,
    assert_nonce_increment_correctness,
};
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
