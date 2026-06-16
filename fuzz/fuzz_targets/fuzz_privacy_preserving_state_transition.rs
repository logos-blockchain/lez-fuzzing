#![cfg_attr(feature = "fuzzer-libfuzzer", no_main)]
//! Path B — full state-transition coverage for the privacy-preserving executor.
//!
//! This is the only target that drives `NSSATransaction::PrivacyPreserving` through
//! `execute_check_on_state` with a proof that *passes* `Proof::is_valid_for`, reaching the
//! previously-0%-covered checks 5 (`check_commitments_are_new`) and 6
//! (`check_nullifiers_are_valid`) and the `apply_state_diff` state mutation. The passing
//! proof is a dev-mode fake receipt synthesised per message+state by
//! [`fuzz_props::privacy::synthesize_passing_proof`] — see that module for the binding
//! caveat. Requires `RISC0_DEV_MODE=1` (set by every `just fuzz` recipe).
//!
//! # Invariants asserted
//!
//! Because the proof is *forced* to pass, balance conservation is intentionally **not**
//! asserted (under a real proof the circuit enforces it, and forcing a pass bypasses exactly
//! that). The properties below all hold regardless of the proof being synthesised:
//!
//! * **No panic** — the executor never crashes on any generated transaction.
//! * **StateIsolationOnFailure / FailedTxNonceStability** — a rejected transaction leaves
//!   public balances and nonces untouched (shared, mutation-tested invariants).
//! * **PrivateStateIsolationOnFailure** — a rejected transaction inserts no commitments.
//! * **CommitmentInsertion** — every commitment in an accepted transaction is a member of
//!   the commitment set afterwards (check 5 reached and applied).
//! * **NonceIncrementCorrectness** — an accepted transaction increments each signer's public
//!   account nonce by exactly one (bug class #5: nonce-increment asymmetry); asserted on
//!   signers not also overwritten as a public post-state.
//! * **PostStateApplied** — each non-signer public account is set to its declared
//!   post-state.
//! * **ReplayRejection** — re-applying an accepted transaction is rejected.

use arbitrary::{Arbitrary, Unstructured};
use common::transaction::LeeTransaction;
use fuzz_props::generators::arbitrary_fuzz_state;
use fuzz_props::invariants::{
    BalanceSnapshot, FailedTxNonceStability, InvariantCtx, NonceSnapshot, ProtocolInvariant,
    StateIsolationOnFailure, assert_nonce_increment_correctness, assert_replay_rejection,
};
use fuzz_props::privacy::arb_privacy_preserving_tx;
use nssa::{AccountId, V03State};

fuzz_props::fuzz_entry!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // Fuzz-driven genesis accounts (with keys) — same approach as fuzz_state_transition.
    let fuzz_accs = match arbitrary_fuzz_state(&mut u) {
        Ok(accs) => accs,
        Err(_) => return,
    };
    let init_accs: Vec<(AccountId, u128)> = fuzz_accs
        .iter()
        .map(|a| (a.account_id, a.balance))
        .collect();
    let mut state = V03State::new_with_genesis_accounts(&init_accs, vec![], 0);

    // Apply a short sequence so multi-transaction state evolution (commitment growth,
    // signer-nonce advance) is exercised. Each transaction's proof is synthesised against
    // the *current* (already-mutated) state.
    let n_txs: u8 = u8::arbitrary(&mut u).unwrap_or(0) % 6;
    for i in 0..n_txs {
        let Ok(tx) = arb_privacy_preserving_tx(&mut u, &state, &fuzz_accs) else {
            break;
        };

        // Capture everything needed for the success-path invariants *before* the
        // transaction is consumed by execution.
        let signer_ids: Vec<AccountId> = tx
            .witness_set()
            .signatures_and_public_keys()
            .iter()
            .map(|(_, pk)| AccountId::from(pk))
            .collect();
        let public_account_ids = tx.message().public_account_ids.clone();
        let public_post_states = tx.message().public_post_states.clone();
        let new_commitments = tx.message().new_commitments.clone();

        let lee_tx = LeeTransaction::PrivacyPreserving(tx);

        // Stateless gate — `WitnessSet::for_message` signs correctly so this passes, but we
        // keep the same gate the production path applies before state transitions.
        let Ok(lee_tx) = lee_tx.transaction_stateless_check() else {
            continue;
        };

        // Track the genesis accounts plus this transaction's signers and public accounts so
        // the isolation snapshots cover every account the transaction could touch.
        let mut tracked: Vec<AccountId> = init_accs.iter().map(|&(id, _)| id).collect();
        for &id in signer_ids.iter().chain(public_account_ids.iter()) {
            if !tracked.contains(&id) {
                tracked.push(id);
            }
        }
        let balances_before = BalanceSnapshot(
            tracked
                .iter()
                .map(|&id| (id, state.get_account_by_id(id).balance))
                .collect(),
        );
        let nonces_before = NonceSnapshot(
            tracked
                .iter()
                .map(|&id| (id, state.get_account_by_id(id).nonce))
                .collect(),
        );
        let digest_before = state.commitment_set_digest();

        let block_id: u64 = 1 + u64::from(i);
        let timestamp: u64 = u64::from(i);
        let state_before = state.clone();

        let result = lee_tx.execute_check_on_state(&mut state, block_id, timestamp);
        let succeeded = result.is_ok();

        // ── Failure-path isolation (shared, mutation-tested invariants) ──────────────
        let ctx = InvariantCtx {
            state_before: &state_before,
            state_after: &state,
            execution_succeeded: succeeded,
            balances_before: balances_before.clone(),
            nonces_before: nonces_before.clone(),
        };
        if let Some(v) = StateIsolationOnFailure.check(&ctx) {
            panic!("INVARIANT VIOLATION [{}]: {}", v.invariant, v.message);
        }
        if let Some(v) = FailedTxNonceStability.check(&ctx) {
            panic!("INVARIANT VIOLATION [{}]: {}", v.invariant, v.message);
        }
        if !succeeded {
            // A rejected privacy-preserving transaction must not touch private state.
            assert_eq!(
                state.commitment_set_digest(),
                digest_before,
                "INVARIANT VIOLATION [PrivateStateIsolationOnFailure]: commitment set changed \
                 despite privacy-preserving transaction rejection",
            );
        }

        if let Ok(applied_tx) = result {
            // Check 5 reached and applied: every accepted commitment is now a member.
            for commitment in &new_commitments {
                assert!(
                    state.get_proof_for_commitment(commitment).is_some(),
                    "INVARIANT VIOLATION [CommitmentInsertion]: accepted commitment was not \
                     inserted into the commitment set",
                );
            }

            // Bug class #5 — the privacy path increments the nonce on the signer's *public*
            // account. Assert it for signers that are not also overwritten verbatim by a
            // public post-state (those are set then incremented, so nonce_before+1 need not
            // hold).
            let isolated_signers: Vec<AccountId> = signer_ids
                .iter()
                .copied()
                .filter(|id| !public_account_ids.contains(id))
                .collect();
            assert_nonce_increment_correctness(&isolated_signers, &nonces_before, &state);

            // Non-signer public accounts at applied indices are set to their post-state.
            for (idx, id) in public_account_ids.iter().enumerate() {
                if idx >= public_post_states.len() {
                    break; // zip in apply_state_diff truncates to the shorter vector
                }
                if signer_ids.contains(id) {
                    continue; // signer accounts also get a nonce increment afterwards
                }
                assert_eq!(
                    state.get_account_by_id(*id),
                    public_post_states[idx],
                    "INVARIANT VIOLATION [PostStateApplied]: public account was not set to its \
                     declared post-state",
                );
            }

            // An accepted transaction must be rejected on replay (spent nullifier / reused
            // commitment / advanced nonce / diverged proof journal).
            assert_replay_rejection(applied_tx, &mut state, block_id + 1, timestamp + 1);
        }
    }
});
