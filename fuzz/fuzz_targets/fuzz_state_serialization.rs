#![no_main]
//! Fuzz target: `V03State` Borsh serialization/deserialization.
//!
//! The state blob is transmitted between nodes and persisted to disk, so a panic or
//! non-idempotent decode is a network-halt severity bug.
//!
//! # Invariants
//!
//! 1. **NoPanic** — `borsh::from_slice::<V03State>(data)` never panics on
//!    arbitrary bytes; it may return `Ok` or `Err`, but must not abort the process.
//!
//! 2. **StateSerializationRoundtrip** — once deserialized, re-encoding and
//!    re-decoding must produce byte-identical output:
//!    `to_vec(from_slice(to_vec(from_slice(data)))) == to_vec(from_slice(data))`.
//!    This catches non-idempotent decode/encode cycles that would corrupt state
//!    across node restarts.
//!
//! 3. **NullifierDeduplication** — the `NullifierSet` Borsh deserializer
//!    explicitly rejects duplicate nullifiers with an `Err`, never a panic.
//!    This invariant is subsumed by invariant 1 but we call it out explicitly
//!    because it is a hand-written `BorshDeserialize` impl — the most likely
//!    place for a logic bug — and the fuzzer should be steered towards exercising
//!    the duplicate-nullifier code path.

use libfuzzer_sys::fuzz_target;
use nssa::V03State;

fuzz_target!(|data: &[u8]| {
    // ── Invariant 1: NoPanic ──────────────────────────────────────────────────
    // `borsh::from_slice` must never panic.  If it returns `Err`, we simply
    // return early; only structurally valid blobs proceed to the round-trip check.
    let Ok(state) = borsh::from_slice::<V03State>(data) else {
        return;
    };

    // ── Invariant 2: StateSerializationRoundtrip ──────────────────────────────
    // Re-encode the successfully decoded state.
    let re_encoded = borsh::to_vec(&state)
        .expect("INVARIANT VIOLATION [StateSerializationRoundtrip]: \
                 borsh::to_vec of a successfully decoded V03State must not fail");

    // Decode a second time.
    let state2 = borsh::from_slice::<V03State>(&re_encoded)
        .expect("INVARIANT VIOLATION [StateSerializationRoundtrip]: \
                 borsh::from_slice of a V03State that was decoded-then-re-encoded \
                 must always succeed (round-trip must be stable)");

    // Re-encode the second decode — must produce byte-identical output.
    let re_encoded2 = borsh::to_vec(&state2)
        .expect("INVARIANT VIOLATION [StateSerializationRoundtrip]: \
                 second borsh::to_vec must not fail");

    assert_eq!(
        re_encoded,
        re_encoded2,
        "INVARIANT VIOLATION [StateSerializationRoundtrip]: \
         encode(decode(encode(decode(data)))) != encode(decode(data)) — \
         V03State Borsh codec is not idempotent"
    );
});
