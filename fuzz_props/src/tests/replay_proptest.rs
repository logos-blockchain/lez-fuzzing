// Run with: cargo test -p fuzz_props replay_rejection
use crate::generators::{arb_native_transfer_tx, test_accounts};
use nssa::V03State;
use proptest::prelude::*;

fn make_test_state() -> V03State {
    let accounts = test_accounts();
    let init_accs: Vec<(nssa::AccountId, u128)> = accounts
        .iter()
        .map(|(id, _)| (*id, 1_000_000_u128))
        .collect();
    V03State::new_with_genesis_accounts(&init_accs, vec![], 0)
}

proptest! {
    /// **ReplayRejection** \u{2014} a transaction accepted in block N must be
    /// rejected when replayed in block N+1, because the nonce is consumed
    /// on first acceptance.
    #[test]
    fn replay_rejection_proptest(tx in arb_native_transfer_tx(test_accounts())) {
        let mut state = make_test_state();

        // Skip structurally invalid transactions (e.g. mismatched public key / sender).
        let Ok(validated_tx) = tx.transaction_stateless_check() else { return Ok(()) };

        // First application may fail for state-level reasons; nothing to replay then.
        let first_result = validated_tx.execute_check_on_state(&mut state, 1, 0);

        if let Ok(applied_tx) = first_result {
            crate::invariants::assert_replay_rejection(applied_tx, &mut state, 2, 1);
        }
    }
}
