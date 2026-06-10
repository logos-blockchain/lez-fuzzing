#![cfg_attr(feature = "fuzzer-libfuzzer", no_main)]
//! Fuzz target: `privacy_preserving_transaction::WitnessSet` invariants.
//!
//! Mirrors `fuzz_witness_set_verification` but for the privacy-preserving
//! witness set, which additionally holds a ZK `Proof` alongside the ECDSA
//! signatures.
//!
//! # Invariants
//!
//! 1. **CorrectVerification** — a `WitnessSet` built for message A via
//!    `WitnessSet::for_message` must pass `signatures_are_valid_for(A)`.
//!
//! 2. **MessageIsolation** — the same `WitnessSet` must NOT pass
//!    `signatures_are_valid_for(B)` when B borsh-encodes differently from A.
//!
//! 3. **SignaturesAndPublicKeysNonEmpty** — after `for_message` with N keys,
//!    `signatures_and_public_keys()` must return N entries.
//!
//! 4. **SignerIdsMatchWitnessKeys** — `PrivacyPreservingTransaction::signer_account_ids`
//!    must equal `AccountId::from(pk)` for every key in the witness set.

use arbitrary::{Arbitrary, Unstructured};
use fuzz_props::arbitrary_types::ArbPrivateKey;
use nssa::{
    AccountId, PrivateKey, PublicKey,
    privacy_preserving_transaction::{
        Message as PPMessage,
        WitnessSet as PPWitnessSet,
        circuit::Proof,
    },
    PrivacyPreservingTransaction,
};
use nssa_core::{
    account::Nonce,
    program::{BlockValidityWindow, TimestampValidityWindow},
};

/// Build a minimal `Message` for testing — no commitments, no nullifiers,
/// no encrypted states.  Sufficient to test signature binding.
fn minimal_message(account_ids: Vec<AccountId>, nonces: Vec<Nonce>) -> PPMessage {
    PPMessage {
        public_account_ids: account_ids,
        nonces,
        public_post_states: vec![],
        encrypted_private_post_states: vec![],
        new_commitments: vec![],
        new_nullifiers: vec![],
        block_validity_window: BlockValidityWindow::new_unbounded(),
        timestamp_validity_window: TimestampValidityWindow::new_unbounded(),
    }
}

/// Build a minimal (fake) `Proof` — bytes don't form a real ZK receipt but
/// are valid for struct construction and serialisation.
fn fake_proof() -> Proof {
    Proof::from_inner(vec![0xAB_u8; 32])
}

fuzz_props::fuzz_entry!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // ── Fixed-key deterministic part ──────────────────────────────────────────
    // Always runs regardless of input length, ensuring the mutation is caught
    // even on an empty corpus.
    {
        let key1 = PrivateKey::try_new([1_u8; 32]).expect("known-good key");
        let key2 = PrivateKey::try_new([2_u8; 32]).expect("known-good key");
        let pub1 = PublicKey::new_from_private_key(&key1);
        let pub2 = PublicKey::new_from_private_key(&key2);
        let addr1 = AccountId::from(&pub1);
        let addr2 = AccountId::from(&pub2);

        let msg = minimal_message(
            vec![addr1, addr2],
            vec![Nonce::from(0_u128), Nonce::from(1_u128)],
        );

        let ws = PPWitnessSet::for_message(&msg, fake_proof(), &[&key1, &key2]);

        // ── INVARIANT [SignaturesAndPublicKeysNonEmpty] ───────────────────────
        assert_eq!(
            ws.signatures_and_public_keys().len(),
            2,
            "INVARIANT VIOLATION [SignaturesAndPublicKeysNonEmpty]: \
             signatures_and_public_keys must return 2 entries for a 2-key witness set",
        );

        // ── INVARIANT [CorrectVerification] ───────────────────────────────────
        assert!(
            ws.signatures_are_valid_for(&msg),
            "INVARIANT VIOLATION [CorrectVerification]: \
             WitnessSet::for_message produced a witness set that fails \
             signatures_are_valid_for on the same message",
        );

        // ── INVARIANT [SignerIdsMatchWitnessKeys] ─────────────────────────────
        // signer_account_ids is pub(crate); derive from signatures_and_public_keys instead.
        let signers_from_ws: Vec<AccountId> = ws
            .signatures_and_public_keys()
            .iter()
            .map(|(_, pk)| AccountId::from(pk))
            .collect();
        assert_eq!(signers_from_ws.len(), 2);
        assert!(signers_from_ws.contains(&addr1));
        assert!(signers_from_ws.contains(&addr2));

        // ── INVARIANT [SignerOnlyAccountInAffected] ───────────────────────────
        // `PrivacyPreservingTransaction::affected_public_account_ids` unions
        // `signer_account_ids()` with `message.public_account_ids`.  To catch the
        // `signer_account_ids → vec![]` mutation, build a message whose
        // public_account_ids does NOT contain the signer, so the signer can only
        // reach `affected` via `signer_account_ids()`.
        let isolated_msg = minimal_message(
            vec![AccountId::new([0xB1_u8; 32]), AccountId::new([0xB2_u8; 32])],
            vec![Nonce::from(0_u128), Nonce::from(1_u128)],
        );
        // Sign with key1 — addr1 is (with overwhelming probability) not one of the
        // 0xB1/0xB2 placeholder accounts.
        if addr1 != AccountId::new([0xB1_u8; 32]) && addr1 != AccountId::new([0xB2_u8; 32]) {
            let isolated_ws = PPWitnessSet::for_message(&isolated_msg, fake_proof(), &[&key1]);
            let isolated_tx =
                PrivacyPreservingTransaction::new(isolated_msg, isolated_ws);
            let affected = isolated_tx.affected_public_account_ids();
            assert!(
                affected.contains(&addr1),
                "INVARIANT VIOLATION [SignerOnlyAccountInAffected]: \
                 PP affected_public_account_ids must include the signer {:?} even when it \
                 is absent from message.public_account_ids — signer_account_ids() must not \
                 return an empty vec",
                addr1,
            );
        }

        // ── INVARIANT [MessageIsolation] ──────────────────────────────────────
        // Build a different message (different nonces) — the witness set for msg
        // must NOT validate against msg_b.
        let msg_b = minimal_message(
            vec![addr1, addr2],
            vec![Nonce::from(999_u128), Nonce::from(1000_u128)],
        );
        let bytes_a = borsh::to_vec(&msg);
        let bytes_b = borsh::to_vec(&msg_b);
        if let (Ok(a), Ok(b)) = (bytes_a, bytes_b) {
            if a != b {
                assert!(
                    !ws.signatures_are_valid_for(&msg_b),
                    "INVARIANT VIOLATION [MessageIsolation]: \
                     PP WitnessSet for msg accepted for a different msg_b — \
                     possible signature-binding bypass",
                );
            }
        }

        // Single-key variant:
        let ws_single = PPWitnessSet::for_message(&msg, fake_proof(), &[&key1]);
        assert_eq!(ws_single.signatures_and_public_keys().len(), 1);

        let tx_single = PrivacyPreservingTransaction::new(msg.clone(), ws_single);
        // Use affected_public_account_ids (which calls signer_account_ids internally):
        let single_affected = tx_single.affected_public_account_ids();
        assert!(
            single_affected.contains(&addr1),
            "INVARIANT VIOLATION [SignerIdsMatchWitnessKeys]: 1-key tx must include addr1",
        );
    }

    // ── Fuzz-driven part ──────────────────────────────────────────────────────
    // Generate 0–3 random private keys, build a WitnessSet, verify correct validation.
    {
        let n_keys = (u8::arbitrary(&mut u).unwrap_or(0) % 4) as usize;
        let mut keys = Vec::with_capacity(n_keys);
        let mut addrs = Vec::with_capacity(n_keys);
        let mut nonces = Vec::with_capacity(n_keys);

        for i in 0..n_keys {
            match ArbPrivateKey::arbitrary(&mut u) {
                Ok(k) => {
                    let pk = PublicKey::new_from_private_key(&k.0);
                    addrs.push(AccountId::from(&pk));
                    nonces.push(Nonce::from(i as u128));
                    keys.push(k.0);
                }
                Err(_) => break,
            }
        }

        if keys.is_empty() {
            return;
        }

        let msg = minimal_message(addrs.clone(), nonces);
        let key_refs: Vec<&PrivateKey> = keys.iter().collect();
        let ws = PPWitnessSet::for_message(&msg, fake_proof(), &key_refs);

        // INVARIANT [SignaturesAndPublicKeysNonEmpty]
        assert_eq!(
            ws.signatures_and_public_keys().len(),
            keys.len(),
            "INVARIANT VIOLATION [SignaturesAndPublicKeysNonEmpty]: \
             signatures_and_public_keys count must match number of keys",
        );

        // INVARIANT [CorrectVerification]
        assert!(
            ws.signatures_are_valid_for(&msg),
            "INVARIANT VIOLATION [CorrectVerification]: \
             PP WitnessSet::for_message produced witnesses that fail validation",
        );

        // INVARIANT [SignerIdsMatchWitnessKeys]
        // signer_account_ids is pub(crate); verify via affected_public_account_ids
        // (which internally calls signer_account_ids) and via signatures_and_public_keys.
        let tx = PrivacyPreservingTransaction::new(msg, ws.clone());
        let signer_ids_from_ws: Vec<AccountId> = ws
            .signatures_and_public_keys()
            .iter()
            .map(|(_, pk)| AccountId::from(pk))
            .collect();
        assert_eq!(
            signer_ids_from_ws.len(),
            addrs.len(),
            "INVARIANT VIOLATION [SignerIdsMatchWitnessKeys]: \
             witness set key count must match number of keys provided",
        );
        // affected_public_account_ids includes signer IDs:
        let affected2 = tx.affected_public_account_ids();
        for addr in &addrs {
            assert!(
                affected2.contains(addr),
                "INVARIANT VIOLATION [SignerIdsMatchWitnessKeys]: \
                 affected_public_account_ids must contain {:?}",
                addr,
            );
        }
    }
});
