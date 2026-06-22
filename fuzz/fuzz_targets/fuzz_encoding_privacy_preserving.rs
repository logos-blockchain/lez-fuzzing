#![cfg_attr(feature = "fuzzer-libfuzzer", no_main)]
//! Fuzz target: privacy-preserving encoding invariants.
//!
//! Tests that `to_bytes` / `from_bytes` round-trips work correctly for the
//! privacy-preserving `Message` type, and that `try_from_circuit_output`
//! maps each circuit-output field onto the resulting `Message` unchanged.
//!
//! `PrivacyPreservingTransaction` is also tested for serialisation stability
//! (non-empty, deterministic bytes) without requiring a real ZK receipt.

use nssa::{
    AccountId, PrivateKey, PublicKey,
    PrivacyPreservingTransaction,
    privacy_preserving_transaction::{
        Message as PPMessage,
        WitnessSet as PPWitnessSet,
        circuit::Proof,
    },
};
use nssa_core::{
    Commitment, PrivacyPreservingCircuitOutput,
    account::{Account, Nonce},
    program::{BlockValidityWindow, TimestampValidityWindow},
};

/// Build a minimal `Message` with no private state.
fn minimal_message() -> PPMessage {
    let addr = AccountId::from(
        &PublicKey::new_from_private_key(
            &PrivateKey::try_new([1_u8; 32]).expect("known-good"),
        ),
    );
    PPMessage {
        public_account_ids: vec![addr],
        nonces: vec![Nonce::from(0_u128)],
        public_post_states: vec![],
        encrypted_private_post_states: vec![],
        new_commitments: vec![],
        new_nullifiers: vec![],
        block_validity_window: BlockValidityWindow::new_unbounded(),
        timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
    }
}

fuzz_props::fuzz_entry!(|data: &[u8]| {
    // ── INVARIANT [MessageEncodingRoundtrip] ──────────────────────────────────
    // `Message::to_bytes()` followed by `Message::from_bytes()` must reproduce
    // the original message.  Catches mutations that return `vec![]`, `vec![0]`,
    // or `vec![1]` — these break round-trip identity.
    {
        let msg = minimal_message();
        let encoded = msg.to_bytes();

        // Non-empty: catches `→ vec![]`
        assert!(
            !encoded.is_empty(),
            "INVARIANT VIOLATION [MessageEncodingRoundtrip]: \
             Message::to_bytes must not return an empty vec",
        );

        let decoded = PPMessage::from_bytes(&encoded)
            .expect("INVARIANT VIOLATION [MessageEncodingRoundtrip]: \
                     from_bytes(to_bytes(msg)) must succeed");

        let re_encoded = decoded.to_bytes();
        assert_eq!(
            encoded,
            re_encoded,
            "INVARIANT VIOLATION [MessageEncodingRoundtrip]: \
             encode(decode(encode(msg))) != encode(msg)",
        );
    }

    // ── INVARIANT [TxEncodingNonEmpty] / [TxEncodingDeterministic] ────────────
    // `PrivacyPreservingTransaction::to_bytes()` must return a non-empty byte
    // slice and be deterministic.  Catches mutations that return `vec![]` etc.
    {
        let key = PrivateKey::try_new([1_u8; 32]).expect("known-good");
        let msg = minimal_message();
        let proof = Proof::from_inner(vec![0xDE_u8, 0xAD, 0xBE, 0xEF]);
        let ws = PPWitnessSet::for_message(&msg, proof, &[&key]);
        let tx = PrivacyPreservingTransaction::new(msg, ws);

        let bytes1 = tx.to_bytes();
        assert!(
            !bytes1.is_empty(),
            "INVARIANT VIOLATION [TxEncodingNonEmpty]: \
             PrivacyPreservingTransaction::to_bytes must not be empty",
        );

        let bytes2 = tx.to_bytes();
        assert_eq!(
            bytes1,
            bytes2,
            "INVARIANT VIOLATION [TxEncodingDeterministic]: \
             to_bytes must be deterministic — called twice, got different results",
        );

        // Verify round-trip for the full transaction:
        let decoded = PrivacyPreservingTransaction::from_bytes(&bytes1)
            .expect("INVARIANT VIOLATION: round-trip decode must succeed");
        assert_eq!(
            bytes1,
            decoded.to_bytes(),
            "INVARIANT VIOLATION [TxEncodingDeterministic]: \
             encode(decode(encode(tx))) != encode(tx)",
        );
    }

    // ── INVARIANT [CircuitOutputMapping] ──────────────────────────────────────
    // `try_from_circuit_output` carries each circuit-output field onto the resulting
    // `Message` unchanged, and threads through the caller-supplied public_account_ids /
    // nonces.  The function is infallible (it performs no validation of its own), so a
    // bare `is_ok()` would be a tautology; instead assert the field mapping, which catches
    // a mutation that drops, swaps, or defaults any carried field.
    {
        let addr = AccountId::from(
            &PublicKey::new_from_private_key(
                &PrivateKey::try_new([1_u8; 32]).expect("known-good"),
            ),
        );
        let account_ids = vec![addr];
        let nonces = vec![Nonce::from(7_u128)];
        let post_states = vec![Account::default()];
        let commitments =
            vec![Commitment::new(&AccountId::new([9_u8; 32]), &Account::default())];

        let output = PrivacyPreservingCircuitOutput {
            public_pre_states: vec![],
            public_post_states: post_states.clone(),
            new_commitments: commitments.clone(),
            new_nullifiers: vec![],
            encrypted_private_post_states: vec![],
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
        };

        let msg = PPMessage::try_from_circuit_output(account_ids.clone(), nonces.clone(), output)
            .expect("INVARIANT VIOLATION [CircuitOutputMapping]: \
                     try_from_circuit_output is infallible and must accept any output");

        assert_eq!(
            msg.public_account_ids, account_ids,
            "INVARIANT VIOLATION [CircuitOutputMapping]: \
             public_account_ids not threaded through unchanged",
        );
        assert_eq!(
            msg.nonces, nonces,
            "INVARIANT VIOLATION [CircuitOutputMapping]: nonces not threaded through unchanged",
        );
        assert_eq!(
            msg.public_post_states, post_states,
            "INVARIANT VIOLATION [CircuitOutputMapping]: \
             public_post_states not carried from the circuit output",
        );
        assert_eq!(
            msg.new_commitments, commitments,
            "INVARIANT VIOLATION [CircuitOutputMapping]: \
             new_commitments not carried from the circuit output",
        );
    }

    // ── Raw fuzz decode tests ─────────────────────────────────────────────────
    // Fuzz the Message decoder for no-panic and canonical round-trip.
    {
        // No-panic on arbitrary bytes:
        let _ = PPMessage::from_bytes(data);

        // Canonical round-trip: if fuzz bytes decode, re-encoding must reproduce them.
        if let Ok(msg) = PPMessage::from_bytes(data) {
            let re_encoded = msg.to_bytes();
            assert_eq!(
                data,
                re_encoded.as_slice(),
                "INVARIANT VIOLATION: PP Message decoded from raw bytes but \
                 re-encoding differs (non-canonical encoding accepted)",
            );
        }
    }

    // ── Varied-size message round-trips ──────────────────────────────────────
    // Verify round-trip for several multi-account messages.
    for n_accounts in [0, 1, 2, 3] {
        let mut account_ids = Vec::new();
        let mut nonces = Vec::new();
        for i in 0..n_accounts {
            let key_bytes = [i + 1_u8; 32];
            if let Ok(key) = PrivateKey::try_new(key_bytes) {
                let pk = PublicKey::new_from_private_key(&key);
                account_ids.push(AccountId::from(&pk));
                nonces.push(Nonce::from(i as u128));
            }
        }

        let msg = PPMessage {
            public_account_ids: account_ids,
            nonces,
            public_post_states: vec![],
            encrypted_private_post_states: vec![],
            new_commitments: vec![],
            new_nullifiers: vec![],
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
        };

        let encoded = msg.to_bytes();
        assert!(
            !encoded.is_empty(),
            "INVARIANT VIOLATION [MessageEncodingRoundtrip]: \
             Message::to_bytes must not be empty for a {n_accounts}-account message",
        );

        let decoded = PPMessage::from_bytes(&encoded)
            .expect("round-trip must succeed for well-formed message");
        assert_eq!(
            encoded,
            decoded.to_bytes(),
            "INVARIANT VIOLATION [MessageEncodingRoundtrip]: \
             round-trip failed for {n_accounts}-account message",
        );
    }
});
