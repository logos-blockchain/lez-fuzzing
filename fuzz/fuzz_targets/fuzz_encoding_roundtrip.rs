#![no_main]
//! Fuzz target: encoding round-trip for all transaction types.
//!
//! Invariants exercised:
//!
//! 1. **Encode/decode stability** — `encode(decode(encode(tx))) == encode(tx)`.
//! 2. **Canonical encoding** — if raw fuzzer bytes decode successfully, re-encoding must
//!    reproduce those exact bytes (`encode(decode(data)) == data`). This catches non-canonical
//!    encodings that are accepted by the decoder but silently normalised on the way out.
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

    // ── Test 3: Canonical encoding — raw bytes that decode must re-encode identically ──
    if let Ok(tx) = PublicTransaction::from_bytes(data) {
        let re_encoded = tx.to_bytes();
        assert_eq!(
            data,
            re_encoded.as_slice(),
            "INVARIANT VIOLATION: PublicTransaction decoded from raw fuzzer bytes but \
             re-encoding differs from the original input (non-canonical encoding accepted)"
        );
    }

    // ── Test 4: Canonical encoding for ProgramDeploymentTransaction ──────────────────
    if let Ok(tx) = ProgramDeploymentTransaction::from_bytes(data) {
        let re_encoded = tx.to_bytes();
        assert_eq!(
            data,
            re_encoded.as_slice(),
            "INVARIANT VIOLATION: ProgramDeploymentTransaction decoded from raw fuzzer bytes \
             but re-encoding differs from the original input (non-canonical encoding accepted)"
        );
    }
});
