use common::transaction::LeeTransaction;
use nssa::V03State;
use nssa_core::account::Nonce;

/// Snapshot of public account balances used for conservation checks.
#[derive(Clone, Debug)]
pub struct BalanceSnapshot(pub std::collections::HashMap<nssa::AccountId, u128>);

impl BalanceSnapshot {
    /// Sum of all recorded account balances.
    ///
    /// # Panics
    ///
    /// Panics if the sum overflows `u128`.  This indicates a token-inflation bug — i.e.
    /// the protocol somehow created tokens past `u128::MAX` — and would have been silently
    /// masked by `saturating_add`.  The generator caps each account balance at
    /// `u128::MAX / 8` so eight accounts never overflow; any overflow here is therefore
    /// a genuine protocol violation, not a fuzzer artefact.
    #[must_use]
    pub fn total(&self) -> u128 {
        self.0
            .values()
            .copied()
            .try_fold(0_u128, u128::checked_add)
            .expect(
                "INVARIANT VIOLATION [BalanceOverflow]: sum of account balances exceeded u128::MAX \
                 \u{2014} token-inflation bug that saturating_add would have silently masked",
            )
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
                            "balance changed despite tx rejection: account {acc_id:?} had \
                             {expected_balance} before, {actual_balance} after",
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

    // Overflow in the balance sum IS the violation; using `?` here would silently return
    // `None` and skip the check, which is worse than the inflation bug it was meant to catch.
    #[expect(
        clippy::unwrap_in_result,
        reason = "overflow panic is the intended signal"
    )]
    fn check(&self, ctx: &InvariantCtx<'_>) -> Option<InvariantViolation> {
        if ctx.execution_succeeded {
            let total_before = ctx.balances_before.total();
            let total_after: u128 = ctx
                .balances_before
                .0
                .keys()
                .map(|&id| ctx.state_after.get_account_by_id(id).balance)
                .try_fold(0_u128, u128::checked_add)
                .expect(
                    "INVARIANT VIOLATION [BalanceOverflow]: sum of post-execution account balances \
                     exceeded u128::MAX \u{2014} token-inflation bug that saturating_add would \
                     have silently masked",
                );
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
                            "nonce changed despite tx rejection: account {acc_id:?} nonce was \
                             {expected_nonce:?} before, {actual_nonce:?} after \
                             (griefing attack \u{2014} victim nonce permanently burned on failed tx)",
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
/// # Enforcement
///
/// This invariant **cannot** be enforced through [`InvariantCtx`] because the replay
/// check requires re-applying the `LeeTransaction` that `execute_check_on_state`
/// consumes and returns on `Ok`.  It is therefore **not registered** in
/// [`assert_invariants`]; calling `assert_invariants` alone does **not** cover
/// `ReplayRejection`.
///
/// Every fuzz target that performs state transitions **must** call the standalone
/// [`assert_replay_rejection`] function after each successful execution:
///
/// ```rust,ignore
/// if let Ok(applied_tx) = result {
///     assert_replay_rejection(applied_tx, &mut state, block_id + 1, timestamp + 1);
/// }
/// ```
pub struct ReplayRejection;

/// A successfully applied transaction must increment the nonce of every signer account
/// by exactly one.
///
/// # Enforcement
///
/// This invariant **cannot** be enforced through [`InvariantCtx`] because signer
/// account IDs are private to the `nssa` crate and are consumed by `apply_state_diff`
/// before the caller can observe them.  It is therefore **not registered** in
/// [`assert_invariants`]; calling `assert_invariants` alone does **not** cover
/// `NonceIncrementCorrectness`.
///
/// Every fuzz target that performs state transitions **must** call the standalone
/// [`assert_nonce_increment_correctness`] function after each successful execution,
/// passing signer IDs derived from the transaction's witness set:
///
/// ```rust,ignore
/// if let Ok(applied_tx) = result {
///     let signer_ids = signer_account_ids(&applied_tx);
///     assert_nonce_increment_correctness(&signer_ids, &nonces_before, &state);
/// }
/// ```
pub struct NonceIncrementCorrectness;

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
/// `execute_check_on_state` consumes the `LeeTransaction` and returns it on `Ok`,
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
    applied_tx: LeeTransaction,
    state: &mut V03State,
    next_block_id: u64,
    next_timestamp: u64,
) {
    let replay = applied_tx.execute_check_on_state(state, next_block_id, next_timestamp);
    assert!(
        replay.is_err(),
        "INVARIANT VIOLATION [ReplayRejection]: transaction accepted a second time \u{2014} \
         nonce replay not prevented (replay block_id={next_block_id}, \
         replay timestamp={next_timestamp})",
    );
}

/// Assert that every signer account's nonce was incremented by exactly one after a
/// successfully applied transaction.
///
/// Call this immediately after `apply_state_diff` (or `execute_check_on_state`) succeeds,
/// passing the signer IDs derived from the transaction's witness set, the [`NonceSnapshot`]
/// captured **before** execution, and the post-execution state.
///
/// For a `LeeTransaction::Public(tx)`, derive signer IDs as:
///
/// ```rust,ignore
/// let signer_ids: Vec<nssa::AccountId> = tx
///     .witness_set()
///     .signatures_and_public_keys()
///     .iter()
///     .map(|(_, pk)| nssa::AccountId::from(pk))
///     .collect();
/// ```
///
/// For `LeeTransaction::ProgramDeployment`, there are no signers; pass an empty slice.
///
/// # Why a standalone function?
///
/// `apply_state_diff` consumes the `ValidatedStateDiff`, whose `signer_account_ids` field
/// is private to the `nssa` crate.  The caller must therefore derive signer IDs from the
/// transaction's witness set before consuming the diff, and thread them into this helper.
///
/// # Example
///
/// ```rust,ignore
/// let signer_ids = /* derived from tx.witness_set() */;
/// let nonces_before = NonceSnapshot(
///     signer_ids.iter().map(|&id| (id, state.get_account_by_id(id).nonce)).collect(),
/// );
/// state.apply_state_diff(diff);
/// assert_nonce_increment_correctness(&signer_ids, &nonces_before, &state);
/// ```
pub fn assert_nonce_increment_correctness(
    signer_ids: &[nssa::AccountId],
    nonces_before: &NonceSnapshot,
    state_after: &V03State,
) {
    for &id in signer_ids {
        let nonce_before = match nonces_before.0.get(&id) {
            Some(n) => *n,
            None => continue, // Account not in snapshot (e.g. newly created); skip.
        };
        let nonce_after = state_after.get_account_by_id(id).nonce;
        let expected = Nonce(
            nonce_before
                .0
                .checked_add(1)
                .expect("nonce overflow \u{2014} signer nonce at u128::MAX"),
        );
        assert_eq!(
            nonce_after, expected,
            "INVARIANT VIOLATION [NonceIncrementCorrectness]: signer account {id:?} nonce \
             not incremented by 1 after successful transaction \
             \u{2014} before={nonce_before:?}, expected={expected:?}, got={nonce_after:?} \
             (apply_state_diff failed to increment nonce exactly once)",
        );
    }
}

// ── Dispatchers ───────────────────────────────────────────────────────────────

/// Assert the five state-transition invariants for a single `execute_check_on_state` call.
///
/// Covers the invariants that are defined over one transaction execution attempt —
/// both the failure-isolation properties and the success-outcome correctness properties.
/// All are enforced from a single call; no standalone helpers are needed:
///
/// | Invariant | Active when |
/// |-----------|-------------|
/// | [`StateIsolationOnFailure`] | `execution_result` is `Err` |
/// | [`FailedTxNonceStability`] | `execution_result` is `Err` |
/// | [`BalanceConservation`] | `execution_result` is `Ok` |
/// | [`NonceIncrementCorrectness`] | `execution_result` is `Ok` |
/// | [`ReplayRejection`] | `execution_result` is `Ok` |
///
/// # Parameters
///
/// * `state_before` — clone of the state captured **before** `execute_check_on_state`.
/// * `state_after` — live state **after** execution (mutably borrowed for the replay attempt).
/// * `balances_before` — per-account balance snapshot captured before execution.
/// * `nonces_before` — per-account nonce snapshot captured before execution.
/// * `execution_result` — the `Result` returned by `execute_check_on_state`.
/// * `replay_context` — `(next_block_id, next_timestamp)` used for the mandatory replay attempt.
///
/// # Usage
///
/// ```rust,ignore
/// let state_snapshot = state.clone();
/// let balances_before = BalanceSnapshot(
///     accounts.iter().map(|&(id, _)| (id, state.get_account_by_id(id).balance)).collect(),
/// );
/// let nonces_before = NonceSnapshot(
///     accounts.iter().map(|&(id, _)| (id, state.get_account_by_id(id).nonce)).collect(),
/// );
/// let result = tx.execute_check_on_state(&mut state, block_id, timestamp);
///
/// assert_tx_execution_invariants(
///     &state_snapshot,
///     &mut state,
///     balances_before,
///     nonces_before,
///     result,
///     (block_id + 1, timestamp + 1),
/// );
/// ```
pub fn assert_tx_execution_invariants<E>(
    state_before: &V03State,
    state_after: &mut V03State,
    balances_before: BalanceSnapshot,
    nonces_before: NonceSnapshot,
    execution_result: Result<LeeTransaction, E>,
    replay_context: (u64, u64),
) {
    let execution_succeeded = execution_result.is_ok();
    // Clone nonces_before before it is moved into InvariantCtx so the clone
    // remains available for assert_nonce_increment_correctness on the success path.
    let nonces_for_nonce_check = nonces_before.clone();

    // ── Three InvariantCtx-based invariants ───────────────────────────────────
    // The shared reborrow of state_after ends when assert_invariants returns (NLL),
    // after which state_after is available mutably again for the replay attempt.
    assert_invariants(&InvariantCtx {
        state_before,
        state_after: &*state_after,
        execution_succeeded,
        balances_before,
        nonces_before,
    });

    // ── Two success-only invariants ───────────────────────────────────────────
    if let Ok(applied_tx) = execution_result {
        // Derive signer IDs from the witness set.  ProgramDeployment has no signers.
        let signer_ids: Vec<nssa::AccountId> = match &applied_tx {
            LeeTransaction::Public(pt) => pt
                .witness_set()
                .signatures_and_public_keys()
                .iter()
                .map(|(_, pk)| nssa::AccountId::from(pk))
                .collect(),
            LeeTransaction::PrivacyPreserving(pt) => pt
                .witness_set()
                .signatures_and_public_keys()
                .iter()
                .map(|(_, pk)| nssa::AccountId::from(pk))
                .collect(),
            LeeTransaction::ProgramDeployment(_) => vec![],
        };
        assert_nonce_increment_correctness(&signer_ids, &nonces_for_nonce_check, state_after);
        let (next_block_id, next_timestamp) = replay_context;
        assert_replay_rejection(applied_tx, state_after, next_block_id, next_timestamp);
    }
}

/// Run the three [`InvariantCtx`]-based invariants and panic on the first violation.
///
/// Invariants checked:
///
/// | Invariant | Condition |
/// |-----------|-----------|
/// | [`StateIsolationOnFailure`] | balances unchanged on rejection |
/// | [`BalanceConservation`] | total balance conserved on success |
/// | [`FailedTxNonceStability`] | nonces unchanged on rejection |
///
/// # Prefer [`assert_tx_execution_invariants`] for `execute_check_on_state` call sites
///
/// [`ReplayRejection`] and [`NonceIncrementCorrectness`] are not checked here — they
/// require data unavailable inside [`InvariantCtx`].  Use [`assert_tx_execution_invariants`]
/// instead for any target that calls `execute_check_on_state`; it enforces all five
/// invariants in one call.
///
/// Reserve `assert_invariants` for contexts where no transaction is available for
/// replay (e.g. pure state-serialization or encoding targets).
pub fn assert_invariants(ctx: &InvariantCtx<'_>) {
    let invariants: &[&dyn ProtocolInvariant] = &[
        &StateIsolationOnFailure,
        &BalanceConservation,
        &FailedTxNonceStability,
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
