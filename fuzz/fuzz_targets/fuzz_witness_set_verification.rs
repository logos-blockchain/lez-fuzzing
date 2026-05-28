#![cfg_attr(feature = "fuzzer-libfuzzer", no_main)]
//! Fuzz target: `WitnessSet` authentication isolation for public transactions.
//!
//! The most security-critical property of `WitnessSet` is **message isolation**:
//! a witness set produced for message A must be rejected when presented against
//! message B (when their Borsh encodings differ).  A broken implementation that
//! ignores the message hash or re-uses an inner signature cache across messages
//! would pass every per-signature unit test while being catastrophically insecure.
//!
//! # Invariants
//!
//! 1. **NoPanic** — `WitnessSet::is_valid_for(&msg)` never panics on any
//!    combination of adversarial (signature, public_key) pairs and message.
//!
//! 2. **CorrectVerification** — a `WitnessSet` built by `WitnessSet::for_message`
//!    with a set of private keys always passes `is_valid_for` on the same message.
//!    This is the canonical happy-path invariant for the aggregated auth layer.
//!
//! 3. **MessageIsolation** — when two messages have different Borsh-encoded
//!    representations, a `WitnessSet` built for message A must NOT pass
//!    `is_valid_for` on message B. A false-positive here means arbitrary
//!    transactions could be authorised with stolen witness sets.

use arbitrary::{Arbitrary, Unstructured};
use fuzz_props::arbitrary_types::{ArbPrivateKey, ArbPubTxMessage, ArbWitnessSet};
use nssa::{PublicKey, public_transaction::WitnessSet};

fuzz_props::fuzz_entry!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // ── Invariant 1: NoPanic on adversarial WitnessSet ────────────────────────
    // Feed random (signature, public_key) pairs through `is_valid_for` on a
    // random message.  The result (true/false) is not asserted — we only check
    // there is no panic.
    if let (Ok(ws_wrap), Ok(msg_wrap)) = (
        ArbWitnessSet::arbitrary(&mut u),
        ArbPubTxMessage::arbitrary(&mut u),
    ) {
        let _ = ws_wrap.0.is_valid_for(&msg_wrap.0);
    }

    // ── Invariant 2: CorrectVerification ──────────────────────────────────────
    // Generate a random message and 0–3 signer private keys, build a witness
    // set with `WitnessSet::for_message`, and assert that `is_valid_for` returns
    // `true`.
    if let Ok(msg_wrap) = ArbPubTxMessage::arbitrary(&mut u) {
        let msg = msg_wrap.0;

        // Generate 0–3 private keys
        let n_keys = (u8::arbitrary(&mut u).unwrap_or(0) % 4) as usize;
        let mut keys = Vec::with_capacity(n_keys);
        for _ in 0..n_keys {
            match ArbPrivateKey::arbitrary(&mut u) {
                Ok(k) => keys.push(k.0),
                Err(_) => break,
            }
        }

        let key_refs: Vec<&nssa::PrivateKey> = keys.iter().collect();
        let ws = WitnessSet::for_message(&msg, &key_refs);

        assert!(
            ws.is_valid_for(&msg),
            "INVARIANT VIOLATION [CorrectVerification]: \
             WitnessSet::for_message produced a witness set that fails \
             is_valid_for on the same message"
        );
    }

    // ── Invariant 3: MessageIsolation ─────────────────────────────────────────
    // Build a witness set for message_a, then verify it against message_b.
    // If the two messages Borsh-encode differently, the result must be `false`.
    if let (Ok(msg_a_wrap), Ok(msg_b_wrap)) = (
        ArbPubTxMessage::arbitrary(&mut u),
        ArbPubTxMessage::arbitrary(&mut u),
    ) {
        let msg_a = msg_a_wrap.0;
        let msg_b = msg_b_wrap.0;

        // Encode both messages to compare them.
        let bytes_a = borsh::to_vec(&msg_a);
        let bytes_b = borsh::to_vec(&msg_b);

        // Only assert isolation when the messages are provably distinct.
        let messages_are_distinct = match (&bytes_a, &bytes_b) {
            (Ok(a), Ok(b)) => a != b,
            _ => false, // serialisation failed — skip
        };

        if messages_are_distinct {
            // Sign message_a with an arbitrary key.
            if let Ok(key_wrap) = ArbPrivateKey::arbitrary(&mut u) {
                let private_key = key_wrap.0;
                let _public_key = PublicKey::new_from_private_key(&private_key);
                let ws_for_a = WitnessSet::for_message(&msg_a, &[&private_key]);

                assert!(
                    !ws_for_a.is_valid_for(&msg_b),
                    "INVARIANT VIOLATION [MessageIsolation]: \
                     a WitnessSet built for message_a was accepted as valid for \
                     message_b even though the two messages have different Borsh \
                     encodings — possible signature-binding bypass"
                );
            }
        }
    }
});
