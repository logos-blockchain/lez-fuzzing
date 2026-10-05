#![cfg_attr(feature = "fuzzer-libfuzzer", no_main)]
//! Fuzz target: privacy-preserving encoding invariants.
//!
//! Tests that `to_bytes` / `from_bytes` round-trips work correctly for the
//! privacy-preserving `Message` type, and that `from_circuit_output`
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
        message::PublicActionWithID,
    },
};
use nssa_core::{
    PrivacyPreservingCircuitOutput, PublicAction,
    account::Nonce,
    execution_state::DeferredPublicEffect,
    native_token::NATIVE_TOKEN_PROGRAM_ID,
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
        public_actions: vec![PublicActionWithID {
            account_id: addr,
            effects: vec![],
        }],
        nonces: vec![Nonce::from(0_u128)],
        private_actions: vec![],
        block_validity_window: BlockValidityWindow::new_unbounded(),
        timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
        program_image_claims: vec![],
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
    // `from_circuit_output` carries each circuit-output field onto the resulting
    // `Message` unchanged — every public action's pre-state account id is paired with its
    // post-state, private actions are carried verbatim — and threads through the
    // caller-supplied nonces.  The function performs no validation of its own, so assert
    // the field mapping, which catches a mutation that drops, swaps, or defaults any
    // carried field.
    {
        let addr = AccountId::from(
            &PublicKey::new_from_private_key(
                &PrivateKey::try_new([1_u8; 32]).expect("known-good"),
            ),
        );
        let nonces = vec![Nonce::from(7_u128)];
        let effects = vec![DeferredPublicEffect {
            program_account_id: NATIVE_TOKEN_PROGRAM_ID,
            shard_program_account_id: NATIVE_TOKEN_PROGRAM_ID,
            data: vec![42],
        }];

        let output = PrivacyPreservingCircuitOutput {
            public_actions: vec![PublicAction {
                account_id: addr,
                is_authorized: true,
                effects: effects.clone(),
            }],
            private_actions: vec![],
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
            program_image_claims: vec![],
        };

        let msg = PPMessage::from_circuit_output(nonces.clone(), output);

        assert_eq!(
            msg.public_account_ids(),
            vec![addr],
            "INVARIANT VIOLATION [CircuitOutputMapping]: \
             public action account ids not carried from the circuit output",
        );
        assert_eq!(
            msg.nonces, nonces,
            "INVARIANT VIOLATION [CircuitOutputMapping]: nonces not threaded through unchanged",
        );
        assert_eq!(
            msg.public_actions,
            vec![PublicActionWithID {
                account_id: addr,
                effects,
            }],
            "INVARIANT VIOLATION [CircuitOutputMapping]: \
             public effects not carried from the circuit output",
        );
        assert!(
            msg.private_actions.is_empty(),
            "INVARIANT VIOLATION [CircuitOutputMapping]: \
             private actions must be carried verbatim (here: empty)",
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
        let mut public_actions = Vec::new();
        let mut nonces = Vec::new();
        for i in 0..n_accounts {
            let key_bytes = [i + 1_u8; 32];
            if let Ok(key) = PrivateKey::try_new(key_bytes) {
                let pk = PublicKey::new_from_private_key(&key);
                public_actions.push(PublicActionWithID {
                    account_id: AccountId::from(&pk),
                    effects: vec![],
                });
                nonces.push(Nonce::from(i as u128));
            }
        }

        let msg = PPMessage {
            public_actions,
            nonces,
            private_actions: vec![],
            block_validity_window: BlockValidityWindow::new_unbounded(),
            timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
            program_image_claims: vec![],
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
