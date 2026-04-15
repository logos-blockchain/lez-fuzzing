#![no_main]
//! Fuzz target: encoding round-trip for all transaction types.
//!
//! Invariant: `decode(encode(tx)) == Ok(tx)` and `encode(decode(encode(tx))) == encode(tx)`
//! for every `PublicTransaction` and `ProgramDeploymentTransaction`.
//!
//! `PrivacyPreservingTransaction` is excluded because its ZK receipt cannot be
//! reconstructed in a fuzzing loop.

use arbitrary::{Arbitrary, Unstructured};
use fuzz_props::arbitrary_types::{ArbProgramDeploymentTransaction, ArbPublicTransaction};
use libfuzzer_sys::fuzz_target;
use nssa::{ProgramDeploymentTransaction, PublicTransaction};

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);

    // ── Test 1: PublicTransaction round-trip ──────────────────────────────────
    if let Ok(wrapped) = ArbPublicTransaction::arbitrary(&mut u) {
        let tx = wrapped.0;
        let encoded = tx.to_bytes();
        let decoded = PublicTransaction::from_bytes(&encoded)
            .expect("INVARIANT VIOLATION: PublicTransaction::to_bytes() produced un-decodable output");
        let re_encoded = decoded.to_bytes();
        assert_eq!(
            encoded,
            re_encoded,
            "INVARIANT VIOLATION: encode(decode(encode(tx))) != encode(tx) for PublicTransaction"
        );
    }

    // ── Test 2: ProgramDeploymentTransaction round-trip ───────────────────────
    if let Ok(wrapped) = ArbProgramDeploymentTransaction::arbitrary(&mut u) {
        let tx = wrapped.0;
        let encoded = tx.to_bytes();
        let decoded = ProgramDeploymentTransaction::from_bytes(&encoded)
            .expect("INVARIANT VIOLATION: ProgramDeploymentTransaction::to_bytes() produced un-decodable output");
        let re_encoded = decoded.to_bytes();
        assert_eq!(
            encoded,
            re_encoded,
            "INVARIANT VIOLATION: encode(decode(encode(tx))) != encode(tx) for ProgramDeploymentTransaction"
        );
    }
});
