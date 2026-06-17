use crate::privacy::synthesize_passing_proof;
use nssa::privacy_preserving_transaction::{Message as PPMessage, WitnessSet as PPWitnessSet};
use nssa::{AccountId, PrivacyPreservingTransaction, V03State};
use nssa_core::Commitment;
use nssa_core::account::Account;
use nssa_core::program::{BlockValidityWindow, TimestampValidityWindow};

/// `synthesize_passing_proof` must drive the executor *past* proof verification (check 4)
/// into checks 5–6 and `apply_state_diff`. If the reconstructed journal were even one
/// byte off, `is_valid_for` would return `false` and the executor would stop at check 4 —
/// silently degrading Path B back to Path A.5. This test fails loudly in that case.
///
/// Fake-receipt verification is a pass-through only under `RISC0_DEV_MODE`; the test is a
/// no-op when the variable is unset (e.g. a bare `cargo test`). `just fuzz-props` exports
/// it, as does running with `RISC0_DEV_MODE=1 cargo test`.
#[test]
fn synthesized_proof_reaches_checks_5_6_and_applies() {
    let dev_mode = std::env::var("RISC0_DEV_MODE").is_ok_and(|v| v == "1" || v == "true");
    if !dev_mode {
        return;
    }

    let mut state = V03State::new_with_genesis_accounts(&[], vec![], 0);

    // No signers and a single fresh commitment: checks 1–3 are vacuous/trivially met, so
    // the only way to reach checks 5–6 is for the synthesised proof to pass check 4.
    let aid = AccountId::new([7_u8; 32]);
    let commitment = Commitment::new(&aid, &Account::default());
    let message = PPMessage {
        public_account_ids: vec![],
        nonces: vec![],
        public_post_states: vec![],
        encrypted_private_post_states: vec![],
        new_commitments: vec![commitment.clone()],
        new_nullifiers: vec![],
        block_validity_window: BlockValidityWindow::new_unbounded(),
        timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
    };

    let proof = synthesize_passing_proof(&message, &state, &[]);
    let witness_set = PPWitnessSet::for_message(&message, proof, &[]);
    let tx = PrivacyPreservingTransaction::new(message, witness_set);

    state
        .transition_from_privacy_preserving_transaction(&tx, 1, 0)
        .expect(
            "a synthesised passing proof must drive the executor to success (checks 5-6 + apply)",
        );

    // Check 5 reached and applied: the commitment is now a member of the set.
    assert!(
        state.get_proof_for_commitment(&commitment).is_some(),
        "accepted commitment must be inserted into the commitment set",
    );

    // Replaying the same transaction must now be rejected (commitment already seen).
    assert!(
        state
            .transition_from_privacy_preserving_transaction(&tx, 2, 1)
            .is_err(),
        "replayed transaction must be rejected after its commitment was inserted",
    );
}
