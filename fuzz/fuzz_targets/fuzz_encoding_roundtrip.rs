#![no_main]
//! Fuzz target: encoding round-trip for all transaction types.
//!
//! Invariants exercised:
//!
//! 1. **Encode/decode stability** — `encode(decode(encode(tx))) == encode(tx)`.
//! 2. **No-panic on adversarial bytes** — `from_bytes(raw_fuzz_data)` must never panic,
//!    whether it returns `Ok` or `Err`. (Tests 3 & 4.)
//! 3. **Canonical encoding** — if raw fuzzer bytes decode successfully, re-encoding must
//!    reproduce those exact bytes (`encode(decode(data)) == data`). This catches non-canonical
//!    encodings that are accepted by the decoder but silently normalised on the way out.
//!    Because `borsh::from_slice` (used by `from_bytes`) consumes *all* bytes and errors on
//!    trailing data, `Ok` implies every input byte was semantically meaningful, and the output
//!    must be identical. (Tests 3 & 4, `Ok` branch.)
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

    // ── Test 3: No-panic decode + canonical encoding (PublicTransaction) ─────────────
    // Invariant 2: from_bytes must never panic on any input — Ok or Err both valid, no panic.
    // Invariant 3: on Ok, re-encoding must reproduce the original bytes exactly.
    let pub_raw_result = PublicTransaction::from_bytes(data); // ← no-panic check (invariant 2)
    if let Ok(tx) = pub_raw_result {
        let re_encoded = tx.to_bytes();
        assert_eq!(
            data,
            re_encoded.as_slice(),
            "INVARIANT VIOLATION: PublicTransaction decoded from raw fuzzer bytes but \
             re-encoding differs from the original input (non-canonical encoding accepted)"
        );
    }

    // ── Test 4: No-panic decode + canonical encoding (ProgramDeploymentTransaction) ──
    // Same two invariants as Test 3, applied to ProgramDeploymentTransaction.
    let prog_raw_result = ProgramDeploymentTransaction::from_bytes(data); // ← no-panic check
    if let Ok(tx) = prog_raw_result {
        let re_encoded = tx.to_bytes();
        assert_eq!(
            data,
            re_encoded.as_slice(),
            "INVARIANT VIOLATION: ProgramDeploymentTransaction decoded from raw fuzzer bytes \
             but re-encoding differs from the original input (non-canonical encoding accepted)"
        );
    }
});
