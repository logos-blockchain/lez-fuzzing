#![no_main]
//! Fuzz target: signature creation and verification.
//!
//! Invariants exercised:
//!
//! 1. **Correctness** — `Signature::new(key, msg).is_valid_for(msg, pub_key)` is always `true`
//!    for the matching public key.
//! 2. **No panics** — random (possibly invalid) signatures and public keys must never cause a
//!    panic in `is_valid_for`.
//! 3. **Cross-key soundness** — signing with key A and verifying against key B must not panic
//!    (the result may be `false` or, with negligible probability, accidentally `true`).

use arbitrary::{Arbitrary, Unstructured};
use fuzz_props::arbitrary_types::{ArbPrivateKey, ArbPublicKey, ArbSignature};
use libfuzzer_sys::fuzz_target;
use nssa::{PublicKey, Signature};

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // ── 1. Freshly signed message always verifies with the correct key ─────────
    if let Ok(key_wrap) = ArbPrivateKey::arbitrary(&mut u) {
        let private_key = key_wrap.0;
        let public_key = PublicKey::new_from_private_key(&private_key);
        let msg: [u8; 32] = u.arbitrary().unwrap_or_default();

        let sig = Signature::new(&private_key, &msg);
        assert!(
            sig.is_valid_for(&msg, &public_key),
            "INVARIANT VIOLATION: Signature::new + is_valid_for returned false for the signing key"
        );
    }

    // ── 2. Random bytes as signature must never panic ──────────────────────────
    if let (Ok(sig_wrap), Ok(pk_wrap)) = (
        ArbSignature::arbitrary(&mut u),
        ArbPublicKey::arbitrary(&mut u),
    ) {
        let msg: [u8; 32] = u.arbitrary().unwrap_or_default();
        // The result may be true or false — we only assert no panic.
        let _ = sig_wrap.0.is_valid_for(&msg, &pk_wrap.0);
    }

    // ── 3. Cross-key verification must not panic ───────────────────────────────
    if let (Ok(key_a_wrap), Ok(key_b_wrap)) = (
        ArbPrivateKey::arbitrary(&mut u),
        ArbPrivateKey::arbitrary(&mut u),
    ) {
        let public_b = PublicKey::new_from_private_key(&key_b_wrap.0);
        let msg: [u8; 32] = u.arbitrary().unwrap_or_default();
        let sig_from_a = Signature::new(&key_a_wrap.0, &msg);
        // Must not panic regardless of key mismatch.
        let _ = sig_from_a.is_valid_for(&msg, &public_b);
    }
});
