use common::transaction::NSSATransaction;
use nssa::V03State;
use nssa_core::account::Nonce;

/// Snapshot of public account balances used for conservation checks.
#[derive(Clone, Debug)]
pub struct BalanceSnapshot(pub std::collections::HashMap<nssa::AccountId, u128>);

impl BalanceSnapshot {
    /// Capture current total balance over all known accounts.
    pub fn total(&self) -> u128 {
        self.0.values().copied().fold(0u128, u128::saturating_add)
    }
}

/// Snapshot of account nonces captured before a transaction is applied.
///
/// Mirrors [`BalanceSnapshot`]: one entry per account that should remain
/// stable on a failed transaction (`FailedTxNonceStability` invariant).
#[derive(Clone, Debug)]
pub struct NonceSnapshot(pub std::collections::HashMap<nssa::AccountId, Nonce>);

/// Shared context threaded through every per-transaction invariant check.
///
/// Build this **after** calling `execute_check_on_state` so that `state_after`
/// reflects the post-execution state and `execution_succeeded` matches the
/// actual outcome.
pub struct InvariantCtx<'a> {
    /// State snapshot captured **before** applying the transaction.
    pub state_before: &'a V03State,
    /// Live state **after** applying (or attempting) the transaction.
    pub state_after: &'a V03State,
    /// `true` when `execute_check_on_state` returned `Ok`, `false` on `Err`.
    pub execution_succeeded: bool,
    /// Per-account balances captured before the transaction.
    pub balances_before: BalanceSnapshot,
    /// Per-account nonces captured before the transaction.
    pub nonces_before: NonceSnapshot,
}

/// A named invariant violation with an actionable diagnostic message.
#[derive(Debug)]
pub struct InvariantViolation {
    pub invariant: &'static str,
    pub message: String,
}

/// A protocol rule that can be checked against a single transaction's context.
pub trait ProtocolInvariant {
    fn name(&self) -> &'static str;
    fn check(&self, ctx: &InvariantCtx<'_>) -> Option<InvariantViolation>;
}

// ── Concrete invariants ───────────────────────────────────────────────────────

/// Sum of all public account balances must never change when a transaction is rejected.
///
/// A balance mutation on failure means the protocol leaks state on error paths —
/// e.g., a debit that is not rolled back after a later validation failure.
pub struct StateIsolationOnFailure;

impl ProtocolInvariant for StateIsolationOnFailure {
    fn name(&self) -> &'static str {
        "StateIsolationOnFailure"
    }

    fn check(&self, ctx: &InvariantCtx<'_>) -> Option<InvariantViolation> {
        if !ctx.execution_succeeded {
            for (acc_id, &expected_balance) in &ctx.balances_before.0 {
                let actual_balance = ctx.state_after.get_account_by_id(*acc_id).balance;
                if actual_balance != expected_balance {
                    return Some(InvariantViolation {
                        invariant: self.name(),
                        message: format!(
                            "balance changed despite tx rejection: account {:?} had \
                             {expected_balance} before, {actual_balance} after",
                            acc_id,
                        ),
                    });
                }
            }
        }
        None
    }
}

/// Total balance of all known accounts must be conserved when a transaction succeeds.
///
/// Catches double-credit and token-inflation bugs: a transfer path that credits the
/// recipient without debiting the sender would inflate the sum of all known balances.
/// The check uses the same account set captured in [`BalanceSnapshot`] so that new
/// accounts silently created by execution are NOT included (see known limitation
/// in `fuzz_validate_execute_consistency`).
pub struct BalanceConservation;

impl ProtocolInvariant for BalanceConservation {
    fn name(&self) -> &'static str {
        "BalanceConservation"
    }

    fn check(&self, ctx: &InvariantCtx<'_>) -> Option<InvariantViolation> {
        if ctx.execution_succeeded {
            let total_before = ctx.balances_before.total();
            let total_after: u128 = ctx
                .balances_before
                .0
                .keys()
                .map(|&id| ctx.state_after.get_account_by_id(id).balance)
                .fold(0u128, u128::saturating_add);
            if total_before != total_after {
                return Some(InvariantViolation {
                    invariant: self.name(),
                    message: format!(
                        "total balance of known accounts changed after successful transaction: \
                         before={total_before}, after={total_after} \
                         (possible double-credit or token-inflation bug)",
                    ),
                });
            }
        }
        None
    }
}

/// When a transaction is rejected, every account's nonce must remain unchanged.
///
/// A nonce mutation on a failed transaction constitutes a griefing attack: an
/// adversary could force arbitrary transactions to fail and permanently burn the
/// victim's nonce, rendering their account unusable.
pub struct FailedTxNonceStability;

impl ProtocolInvariant for FailedTxNonceStability {
    fn name(&self) -> &'static str {
        "FailedTxNonceStability"
    }

    fn check(&self, ctx: &InvariantCtx<'_>) -> Option<InvariantViolation> {
        if !ctx.execution_succeeded {
            for (&acc_id, expected_nonce) in &ctx.nonces_before.0 {
                let actual_nonce = ctx.state_after.get_account_by_id(acc_id).nonce;
                if actual_nonce != *expected_nonce {
                    return Some(InvariantViolation {
                        invariant: self.name(),
                        message: format!(
                            "nonce changed despite tx rejection: account {:?} nonce was \
                             {:?} before, {:?} after \
                             (griefing attack — victim nonce permanently burned on failed tx)",
                            acc_id, expected_nonce, actual_nonce,
                        ),
                    });
                }
            }
        }
        None
    }
}

/// A successfully accepted transaction must be rejected when replayed.
///
/// # Note
///
/// This invariant **cannot** be exercised through [`InvariantCtx`] alone because
/// the replay check requires re-applying the `NSSATransaction` that was consumed
/// by `execute_check_on_state`.  The `ProtocolInvariant` impl here is a registry
/// placeholder only; it always returns `None`.
///
/// Use the standalone [`assert_replay_rejection`] function instead, which accepts
/// the `NSSATransaction` returned on success and performs the replay inline.
pub struct ReplayRejection;

impl ProtocolInvariant for ReplayRejection {
    fn name(&self) -> &'static str {
        "ReplayRejection"
    }

    fn check(&self, _ctx: &InvariantCtx<'_>) -> Option<InvariantViolation> {
        // ReplayRejection cannot be fully exercised through InvariantCtx alone.
        // Use `assert_replay_rejection(applied_tx, state, next_block_id, next_ts)` instead.
        None
    }
}

// ── Standalone helpers ────────────────────────────────────────────────────────

/// Assert that a successfully-applied transaction is **rejected** when replayed.
///
/// Call this immediately after `execute_check_on_state` returns `Ok(applied_tx)`,
/// passing `applied_tx` as the first argument.  The transaction is re-applied to
/// `state` at `next_block_id` / `next_timestamp`; if it is accepted a second time
/// the function panics with a structured `INVARIANT VIOLATION [ReplayRejection]`
/// message.
///
/// # Why a standalone function?
///
/// `execute_check_on_state` consumes the `NSSATransaction` and returns it on `Ok`,
/// so the transaction is not available as a shared reference inside [`InvariantCtx`].
/// This function accepts ownership of the returned transaction and performs the
/// replay in-place.
///
/// # Example
///
/// ```rust,ignore
/// let result = tx.execute_check_on_state(&mut state, block_id, timestamp);
/// if let Ok(applied_tx) = result {
///     assert_replay_rejection(applied_tx, &mut state, block_id + 1, timestamp + 1);
/// }
/// ```
pub fn assert_replay_rejection(
    applied_tx: NSSATransaction,
    state: &mut V03State,
    next_block_id: u64,
    next_timestamp: u64,
) {
    let replay = applied_tx.execute_check_on_state(state, next_block_id, next_timestamp);
    assert!(
        replay.is_err(),
        "INVARIANT VIOLATION [ReplayRejection]: transaction accepted a second time — \
         nonce replay not prevented (replay block_id={next_block_id}, \
         replay timestamp={next_timestamp})",
    );
}

// ── Dispatcher ───────────────────────────────────────────────────────────────

/// Run every registered [`ProtocolInvariant`] and panic with a structured message
/// on the first violation.
///
/// Invariants checked:
/// - [`StateIsolationOnFailure`] — balances unchanged on rejection
/// - [`BalanceConservation`] — total balance conserved on success
/// - [`FailedTxNonceStability`] — nonces unchanged on rejection
/// - [`ReplayRejection`] — stub only; use [`assert_replay_rejection`] directly
pub fn assert_invariants(ctx: &InvariantCtx<'_>) {
    let invariants: &[&dyn ProtocolInvariant] = &[
        &StateIsolationOnFailure,
        &BalanceConservation,
        &FailedTxNonceStability,
        &ReplayRejection,
    ];
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

// ── Unit tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use nssa::V03State;

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
    fn invariant_replay_rejection_does_not_panic() {
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
        // Arrange: one account with balance 100.
        let acc_id = nssa::AccountId::new([1u8; 32]);
        let state_before = V03State::new_with_genesis_accounts(&[(acc_id, 100)], vec![], 0);
        // Simulate execution that inflated the balance to 200.
        let state_after = V03State::new_with_genesis_accounts(&[(acc_id, 200)], vec![], 0);

        let mut balances = std::collections::HashMap::new();
        balances.insert(acc_id, 100u128);

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
    fn failed_tx_nonce_stability_catches_nonce_mutation() {
        let acc_id = nssa::AccountId::new([2u8; 32]);
        // before: nonce 5; after: nonce 6 (should not happen on failure)
        let state_before = V03State::new_with_genesis_accounts(&[(acc_id, 100)], vec![], 0);
        let state_after = V03State::new_with_genesis_accounts(&[(acc_id, 100)], vec![], 0);

        // We check the nonce snapshot directly; the states both return default nonce (0).
        // Fake a discrepancy by inserting nonce=1 in the snapshot while state_after has nonce=0.
        let mut nonces = std::collections::HashMap::new();
        // Nonce(1) in snapshot, but state_after will return Nonce(0).
        nonces.insert(acc_id, Nonce(1));

        let mut balances = std::collections::HashMap::new();
        balances.insert(acc_id, 100u128);

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
                // Use the shared framework function.  assert_replay_rejection uses
                // assert!() rather than prop_assert!(); for structured proptest
                // inputs the framework-level panic is equivalent.
                super::assert_replay_rejection(validated_tx, &mut state, 2, 1);
            }
        }
    }
}
