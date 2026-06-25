#![cfg_attr(feature = "fuzzer-libfuzzer", no_main)]
//! Fuzz target: transaction property invariants.
//!
//! Tests that key accessor methods on `LeeTransaction`, `PublicTransaction`, and
//! `ValidatedStateDiff` return correct, non-stub values.

use arbitrary::{Arbitrary, Unstructured};
use common::transaction::LeeTransaction;
use fuzz_props::arbitrary_types::ArbPrivateKey;
use fuzz_props::generators::{arb_fuzz_native_transfer, arbitrary_fuzz_state};
use nssa::{
    AccountId, PrivateKey, PublicKey, ValidatedStateDiff,
    public_transaction::{Message, WitnessSet},
    PublicTransaction,
};
use nssa_core::account::Nonce;

fuzz_props::fuzz_entry!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // ── Part 1: Known-good witness set / transaction using fixed keys ──────────
    // Uses deterministic keys so we always have at least one valid transaction.
    // This ensures hash, signer_account_ids, into_raw_parts, and affected_accounts
    // are always tested, even when the fuzzer input is insufficient for arb generators.
    {
        let key1 = PrivateKey::try_new([1_u8; 32]).expect("known-good key");
        let key2 = PrivateKey::try_new([2_u8; 32]).expect("known-good key");
        let pub1 = PublicKey::new_from_private_key(&key1);
        let pub2 = PublicKey::new_from_private_key(&key2);
        let addr1 = AccountId::from(&pub1);
        let addr2 = AccountId::from(&pub2);

        let nonces = vec![Nonce::from(0_u128), Nonce::from(0_u128)];
        let message = Message::try_new(
            programs::authenticated_transfer().id(),
            vec![addr1, addr2],
            nonces,
            1337_u64,
        )
        .expect("known-good message");

        let ws = WitnessSet::for_message(&message, &[&key1, &key2]);
        let pub_tx = PublicTransaction::new(message, ws);

        // ── INVARIANT [SignerIdsNonEmpty] ─────────────────────────────────────
        // A transaction signed by 2 keys must expose 2 signer (key, sig) pairs.
        // `signer_account_ids` is pub(crate); we verify via the public witness_set API.
        let ws_pairs = pub_tx.witness_set().signatures_and_public_keys();
        assert_eq!(
            ws_pairs.len(),
            2,
            "INVARIANT VIOLATION [SignerIdsNonEmpty]: \
             witness_set signatures_and_public_keys must have 2 entries",
        );

        // ── INVARIANT [IntoRawPartsCount] ─────────────────────────────────────
        // `into_raw_parts` must return the same number of pairs as the witness set.
        // Catches the mutation that returns `vec![]`.
        let ws2 = WitnessSet::for_message(pub_tx.message(), &[&key1, &key2]);
        let parts = ws2.into_raw_parts();
        assert_eq!(
            parts.len(),
            2,
            "INVARIANT VIOLATION [IntoRawPartsCount]: \
             WitnessSet::into_raw_parts must return 2 pairs for a 2-key witness set",
        );

        // ── INVARIANT [AffectedAccountsContainSigners] ───────────────────────
        // `affected_public_account_ids` must include the signer accounts.
        // Catches the mutation that returns `vec![]` or `vec![Default::default()]`.
        let affected = pub_tx.affected_public_account_ids();
        assert!(
            !affected.is_empty(),
            "INVARIANT VIOLATION [AffectedAccountsContainSigners]: \
             affected_public_account_ids must be non-empty for a 2-signer tx",
        );
        assert!(
            affected.contains(&addr1),
            "INVARIANT VIOLATION [AffectedAccountsContainSigners]: \
             affected_public_account_ids must include addr1 (signer)",
        );
        assert!(
            affected.contains(&addr2),
            "INVARIANT VIOLATION [AffectedAccountsContainSigners]: \
             affected_public_account_ids must include addr2 (signer)",
        );

        // ── INVARIANT [HashNonDefault] ────────────────────────────────────────
        // The transaction hash must not be the all-zero default.
        // Catches the mutation that returns `Default::default()`.
        let lee_tx = LeeTransaction::Public(pub_tx);
        let hash = lee_tx.hash();
        assert_ne!(
            hash.0,
            [0_u8; 32],
            "INVARIANT VIOLATION [HashNonDefault]: \
             LeeTransaction::hash must not return all-zero bytes",
        );

        // Also verify it's deterministic (same tx → same hash):
        let hash2 = lee_tx.hash();
        assert_eq!(
            hash,
            hash2,
            "INVARIANT VIOLATION [HashDeterministic]: \
             LeeTransaction::hash must be deterministic",
        );

        // LeeTransaction::affected_public_account_ids must also be non-empty:
        let lee_affected = lee_tx.affected_public_account_ids();
        assert!(
            lee_affected.contains(&addr1),
            "INVARIANT VIOLATION [AffectedAccountsContainSigners]: \
             LeeTransaction::affected_public_account_ids must include addr1",
        );
    }

    // ── INVARIANT [SignerOnlyAccountInAffected] ───────────────────────────────
    // Build a transaction signed by a key whose AccountId is NOT among
    // `message.account_ids`.  Then `affected_public_account_ids` can only contain
    // the signer's AccountId via `signer_account_ids()` — it is absent from the
    // message's account list.  This directly catches the `signer_account_ids`
    // mutations (`→ vec![]` / `→ vec![Default::default()]`) on PublicTransaction,
    // which the earlier checks miss because there the signer also appears in
    // `message.account_ids`.
    {
        // Signer key — its AccountId must NOT appear in the message account list.
        let signer_key = PrivateKey::try_new([9_u8; 32]).expect("known-good key");
        let signer_pub = PublicKey::new_from_private_key(&signer_key);
        let signer_addr = AccountId::from(&signer_pub);

        // Two unrelated account IDs for the message (deterministic, not derived
        // from the signer key).
        let other1 = AccountId::new([0xA1_u8; 32]);
        let other2 = AccountId::new([0xA2_u8; 32]);

        // Guard: ensure the signer is genuinely not one of the message accounts.
        if signer_addr != other1 && signer_addr != other2 {
            let nonces = vec![Nonce::from(0_u128)];
            if let Ok(msg) = Message::try_new(
                programs::authenticated_transfer().id(),
                vec![other1, other2],
                nonces,
                7_u64,
            ) {
                let ws = WitnessSet::for_message(&msg, &[&signer_key]);
                let pt = PublicTransaction::new(msg, ws);

                let affected = pt.affected_public_account_ids();
                assert!(
                    affected.contains(&signer_addr),
                    "INVARIANT VIOLATION [SignerOnlyAccountInAffected]: \
                     affected_public_account_ids must include the signer {:?} even when it \
                     is absent from message.account_ids — signer_account_ids() must not \
                     return an empty (or defaulted) vec",
                    signer_addr,
                );
            }
        }
    }

    // ── Part 2: Fuzz-driven state + valid native transfer ─────────────────────
    // Generates a random state and a correctly-signed transfer.  When the transfer
    // succeeds, verifies that `public_diff` is non-empty and contains the
    // expected account changes.
    {
        let fuzz_accs = match arbitrary_fuzz_state(&mut u) {
            Ok(accs) => accs,
            Err(_) => return,
        };
        let init_accs: Vec<(AccountId, u128)> = fuzz_accs
            .iter()
            .map(|a| (a.account_id, a.balance))
            .collect();
        let state = fuzz_props::genesis::genesis_state(&init_accs, vec![]);

        let Ok(tx) = arb_fuzz_native_transfer(&mut u, &fuzz_accs) else {
            return;
        };
        let Ok(checked) = tx.transaction_stateless_check() else {
            return;
        };

        let pub_tx = match &checked {
            LeeTransaction::Public(pt) => pt,
            _ => return,
        };

        // For a public transaction with signers, affected_public_account_ids must
        // include all signer account IDs.  Derive signers from the public witness API.
        let signers: Vec<AccountId> = pub_tx
            .witness_set()
            .signatures_and_public_keys()
            .iter()
            .map(|(_, pk)| AccountId::from(pk))
            .collect();
        let affected = pub_tx.affected_public_account_ids();
        for signer in &signers {
            assert!(
                affected.contains(signer),
                "INVARIANT VIOLATION [AffectedAccountsContainSigners]: \
                 affected_public_account_ids must include signer {:?}",
                signer,
            );
        }

        // When from_public_transaction succeeds, public_diff must be non-empty
        // (at least the signer nonces are updated).
        // Catches the mutation that returns `HashMap::new()`.
        if let Ok(diff) = ValidatedStateDiff::from_public_transaction(pub_tx, &state, 1, 0) {
            let public_diff = diff.public_diff();

            // The diff must contain at least the signer accounts (nonce updates):
            for signer in &signers {
                // Signers appear in diff because their nonces are updated.
                // If public_diff() returns empty HashMap, this assert fires.
                assert!(
                    public_diff.contains_key(signer),
                    "INVARIANT VIOLATION [PublicDiffNonEmptyOnSuccess]: \
                     public_diff must contain signer account {:?} after successful validation \
                     (nonce must have been updated)",
                    signer,
                );
            }
        }
    }

    // ── Part 3: Fuzz-driven arbitrary keys for additional coverage ─────────────
    {
        if let Ok(key_wrap) = ArbPrivateKey::arbitrary(&mut u) {
            let key = key_wrap.0;
            let pubkey = PublicKey::new_from_private_key(&key);
            let addr = AccountId::from(&pubkey);

            let nonces = vec![Nonce::from(0_u128)];
            if let Ok(msg) = Message::try_new(
                programs::authenticated_transfer().id(),
                vec![addr],
                nonces,
                42_u64,
            ) {
                let ws = WitnessSet::for_message(&msg, &[&key]);
                let pt = PublicTransaction::new(msg, ws);

                // Single-signer checks via witness_set (signer_account_ids is pub(crate)):
                let ws_pairs2 = pt.witness_set().signatures_and_public_keys();
                assert_eq!(
                    ws_pairs2.len(),
                    1,
                    "INVARIANT VIOLATION [SignerIdsNonEmpty]: 1-key witness set must have 1 pair",
                );
                let derived_addr = AccountId::from(&ws_pairs2[0].1);
                assert_eq!(
                    derived_addr,
                    addr,
                    "INVARIANT VIOLATION [SignerIdsDerivedFromKeys]: \
                     derived signer address must match expected addr",
                );

                let ws2 = WitnessSet::for_message(pt.message(), &[&key]);
                let parts = ws2.into_raw_parts();
                assert_eq!(
                    parts.len(),
                    1,
                    "INVARIANT VIOLATION [IntoRawPartsCount]: 1-signer witness set → 1 raw part",
                );
            }
        }
    }
});
