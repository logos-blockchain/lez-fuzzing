use common::transaction::NSSATransaction;
use nssa::{V03State, error::NssaError};

/// Snapshot of public account balances used for conservation checks.
#[derive(Clone, Debug)]
pub struct BalanceSnapshot(pub std::collections::HashMap<nssa::AccountId, u128>);

impl BalanceSnapshot {
    /// Capture current total balance over all known accounts.
    pub fn total(&self) -> u128 {
        self.0.values().copied().fold(0u128, u128::saturating_add)
    }
}

/// Shared context threaded through every invariant check.
pub struct InvariantCtx<'a> {
    pub state_before: &'a V03State,
    pub state_after: &'a V03State,
    pub tx: &'a NSSATransaction,
    pub result: &'a Result<(), NssaError>,
    pub balances_before: BalanceSnapshot,
}

#[derive(Debug)]
pub struct InvariantViolation {
    pub invariant: &'static str,
    pub message: String,
}

pub trait ProtocolInvariant {
    fn name(&self) -> &'static str;
    fn check(&self, ctx: &InvariantCtx<'_>) -> Option<InvariantViolation>;
}

// ── Concrete invariants ───────────────────────────────────────────────────────

/// Sum of all public account balances must never change when a transaction is rejected.
pub struct StateIsolationOnFailure;

impl ProtocolInvariant for StateIsolationOnFailure {
    fn name(&self) -> &'static str {
        "StateIsolationOnFailure"
    }

    fn check(&self, ctx: &InvariantCtx<'_>) -> Option<InvariantViolation> {
        if ctx.result.is_err() {
            for (acc_id, &expected_balance) in &ctx.balances_before.0 {
                let actual_balance = ctx.state_after.get_account_by_id(*acc_id).balance;
                if actual_balance != expected_balance {
                    return Some(InvariantViolation {
                        invariant: self.name(),
                        message: format!(
                            "balance changed despite tx rejection: account {:?} had {expected_balance} before, {actual_balance} after",
                            acc_id,
                        ),
                    });
                }
            }
        }
        None
    }
}

/// A successfully accepted transaction must be rejected when replayed.
pub struct ReplayRejection;

impl ProtocolInvariant for ReplayRejection {
    fn name(&self) -> &'static str {
        "ReplayRejection"
    }

    fn check(&self, _ctx: &InvariantCtx<'_>) -> Option<InvariantViolation> {
        // ReplayRejection cannot be fully exercised through InvariantCtx alone,
        // because the check requires *re-applying* the same ValidatedTransaction
        // to the post-execution state.  InvariantCtx holds `tx: &NSSATransaction`,
        // and `transaction_stateless_check()` consumes `self`, so re-validation
        // from a shared reference is not possible.
        //
        // The invariant is enforced in two complementary ways instead:
        //   1. `fuzz_state_transition.rs` — captures the `ValidatedTransaction`
        //      returned on `Ok` by `execute_check_on_state` and immediately
        //      re-applies it at block_id+1; asserts the replay is rejected.
        //   2. The proptest suite in this module (`replay_rejection_proptest`)
        //      exercises the same property with structured, reproducible inputs.
        None
    }
}

/// Run every registered invariant and panic with a structured message on first violation.
pub fn assert_invariants(ctx: &InvariantCtx<'_>) {
    let invariants: &[&dyn ProtocolInvariant] = &[&StateIsolationOnFailure, &ReplayRejection];
    for inv in invariants {
        if let Some(violation) = inv.check(ctx) {
            panic!(
                "INVARIANT VIOLATION [{inv}]: {msg}",
                inv = violation.invariant,
                msg = violation.message,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nssa::V03State;

    fn make_empty_state() -> V03State {
        //V03State::new_with_genesis_accounts(&[], &[])
        V03State::new_with_genesis_accounts(&[], vec![], 0)
    }

    fn make_empty_snapshot() -> BalanceSnapshot {
        BalanceSnapshot(std::collections::HashMap::new())
    }

    #[test]
    fn invariant_state_isolation_on_failure_does_not_panic_on_error() {
        let state = make_empty_state();
        let tx = common::test_utils::produce_dummy_empty_transaction();
        let result: Result<(), NssaError> = Err(NssaError::InvalidInput("test".to_owned()));
        let ctx = InvariantCtx {
            state_before: &state,
            state_after: &state,
            tx: &tx,
            result: &result,
            balances_before: make_empty_snapshot(),
        };
        // Should not panic — invariant check is a placeholder
        assert_invariants(&ctx);
    }

    #[test]
    fn invariant_replay_rejection_does_not_panic() {
        let state = make_empty_state();
        let tx = common::test_utils::produce_dummy_empty_transaction();
        let result: Result<(), NssaError> = Ok(());
        let ctx = InvariantCtx {
            state_before: &state,
            state_after: &state,
            tx: &tx,
            result: &result,
            balances_before: make_empty_snapshot(),
        };
        assert_invariants(&ctx);
    }
}

// ── ReplayRejection proptest suite ───────────────────────────────────────────
//
// This suite constitutes the formal, reproducible exercise of the ReplayRejection
// invariant.  It generates a realistic initial state and a correctly-signed
// native-transfer transaction, applies it once, and asserts that a second
// application is rejected.
//
// Run with: cargo test -p fuzz_props replay_rejection
#[cfg(test)]
mod replay_proptest {
    use crate::generators::{arb_native_transfer_tx, test_accounts};
    use nssa::V03State;
    use proptest::prelude::*;

    /// Build a `V03State` from the testnet accounts, assigning each a fixed
    /// balance large enough for any reasonable transfer amount.
    fn make_test_state() -> V03State {
        let accounts = test_accounts();
        let init_accs: Vec<(nssa::AccountId, u128)> = accounts
            .iter()
            .map(|(id, _)| (*id, 1_000_000u128))
            .collect();
        V03State::new_with_genesis_accounts(&init_accs, vec![], 0)
    }

    proptest! {
        /// **ReplayRejection** — a transaction accepted in block N must be
        /// rejected when replayed in block N+1, because the nonce is consumed
        /// on first acceptance.
        #[test]
        fn replay_rejection_proptest(tx in arb_native_transfer_tx(test_accounts())) {
            let mut state = make_test_state();

            // Stateless gate — skip structurally invalid transactions (e.g. those
            // whose public key does not match the declared sender).
            let validated_tx = match tx.transaction_stateless_check() {
                Ok(v) => v,
                Err(_) => return Ok(()),
            };

            // First application — may fail for state-level reasons (e.g. sender
            // has insufficient balance, wrong nonce).  In that case there is
            // nothing to replay.
            let first_result = validated_tx.execute_check_on_state(&mut state, 1, 0);

            if let Ok(validated_tx) = first_result {
                // The same ValidatedTransaction is returned on Ok; replay it
                // immediately in the next block.
                let second_result = validated_tx.execute_check_on_state(&mut state, 2, 1);
                prop_assert!(
                    second_result.is_err(),
                    "ReplayRejection violated: transaction accepted a second time (nonce \
                     replay not prevented)"
                );
            }
        }
    }
}
